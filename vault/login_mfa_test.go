// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestParseFactors(t *testing.T) {
	testcases := []struct {
		name                string
		invalidMFAHeaderVal []string
		expectedError       string
	}{
		{
			"two headers with passcode",
			[]string{"passcode", "foo"},
			"found multiple passcodes for the same MFA method",
		},
		{
			"single header with passcode=",
			[]string{"passcode="},
			"invalid passcode",
		},
		{
			"single invalid header",
			[]string{"foo="},
			"found an invalid MFA cred",
		},
		{
			"single header equal char",
			[]string{"=="},
			"found an invalid MFA cred",
		},
		{
			"two headers with passcode=",
			[]string{"passcode=foo", "foo"},
			"found multiple passcodes for the same MFA method",
		},
		{
			"two headers invalid name",
			[]string{"passcode=foo", "passcode=bar"},
			"found multiple passcodes for the same MFA method",
		},
		{
			"two headers, two invalid",
			[]string{"foo", "bar"},
			"found multiple passcodes for the same MFA method",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseMfaFactors(tc.invalidMFAHeaderVal)
			if err == nil {
				t.Fatal("nil error returned")
			}
			if !strings.Contains(err.Error(), tc.expectedError) {
				t.Fatalf("expected %s, got %v", tc.expectedError, err)
			}
		})
	}
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.acme_server",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the ACME server handler.
func (ash *Handler) Provision(ctx caddy.Context) error {
	ash.ctx = ctx
	ash.logger = ctx.Logger()

	// set some defaults
	if ash.CA == "" {
		ash.CA = caddypki.DefaultCAID
	}
	if ash.PathPrefix == "" {
		ash.PathPrefix = defaultPathPrefix
	}
	if ash.Lifetime == 0 {
		ash.Lifetime = caddy.Duration(12 * time.Hour)
	}
	if len(ash.Challenges) > 0 {
		if err := ash.Challenges.validate(); err != nil {
			return err
		}
	}

	ash.warnIfPolicyAllowsAll()

	// get a reference to the configured CA
	appModule, err := ctx.App("pki")
	if err != nil {
		return err
	}
	pkiApp := appModule.(*caddypki.PKI)
	ca, err := pkiApp.GetCA(ctx, ash.CA)
	if err != nil {
		return err
	}

	// make sure leaf cert lifetime is less than the intermediate cert lifetime. this check only
	// applies for caddy-managed intermediate certificates
	if ca.Intermediate == nil && ash.Lifetime >= ca.IntermediateLifetime {
		return fmt.Errorf("certificate lifetime (%s) should be less than intermediate certificate lifetime (%s)", time.Duration(ash.Lifetime), time.Duration(ca.IntermediateLifetime))
	}

	database, err := ash.openDatabase()
	if err != nil {
		return err
	}

	authorityConfig := caddypki.AuthorityConfig{
		SignWithRoot: ash.SignWithRoot,
		AuthConfig: &authority.AuthConfig{
			Provisioners: provisioner.List{
				&provisioner.ACME{
					Name:       ash.CA,
					Challenges: ash.Challenges.toSmallstepType(),
					Options: &provisioner.Options{
						X509: ash.Policy.normalizeRules(),
					},
					Type: provisioner.TypeACME.String(),
					Claims: &provisioner.Claims{
						MinTLSDur:     &provisioner.Duration{Duration: 5 * time.Minute},
						MaxTLSDur:     &provisioner.Duration{Duration: 24 * time.Hour * 365},
						DefaultTLSDur: &provisioner.Duration{Duration: time.Duration(ash.Lifetime)},
					},
				},
			},
		},
		DB: database,
	}

	ash.acmeAuth, err = ca.NewAuthority(authorityConfig)
	if err != nil {
		return err
	}

	ash.acmeDB, err = acmeNoSQL.New(ash.acmeAuth.GetDatabase().(nosql.DB))
	if err != nil {
		return fmt.Errorf("configuring ACME DB: %v", err)
	}

	ash.acmeClient, err = ash.makeClient()
	if err != nil {
		return err
	}

	ash.acmeLinker = acme.NewLinker(
		ash.Host,
		strings.Trim(ash.PathPrefix, "/"),
	)

	// extract its http.Handler so we can use it directly
	r := chi.NewRouter()
	r.Route(ash.PathPrefix, func(r chi.Router) {
		api.Route(r)
	})
	ash.acmeEndpoints = r

	return nil
}

func (ash *Handler) warnIfPolicyAllowsAll() {
	allow := ash.Policy.normalizeAllowRules()
	deny := ash.Policy.normalizeDenyRules()
	if allow != nil || deny != nil {
		return
	}

	allowWildcardNames := ash.Policy != nil && ash.Policy.AllowWildcardNames
	ash.logger.Warn(
		"acme_server policy has no allow/deny rules; order identifiers are unrestricted (allow-all)",
		zap.String("ca", ash.CA),
		zap.Bool("allow_wildcard_names", allowWildcardNames),
	)
}

func (ash Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if strings.HasPrefix(r.URL.Path, ash.PathPrefix) {
		acmeCtx := acme.NewContext(
			r.Context(),
			ash.acmeDB,
			ash.acmeClient,
			ash.acmeLinker,
			nil,
		)
		acmeCtx = authority.NewContext(acmeCtx, ash.acmeAuth)
		r = r.WithContext(acmeCtx)

		ash.acmeEndpoints.ServeHTTP(w, r)
		return nil
	}
	return next.ServeHTTP(w, r)
}

func (ash Handler) getDatabaseKey() string {
	key := ash.CA
	key = strings.ToLower(key)
	key = strings.TrimSpace(key)
	return keyCleaner.ReplaceAllLiteralString(key, "")
}

// Cleanup implements caddy.CleanerUpper and closes any idle databases.
func (ash Handler) Cleanup() error {
	key := ash.getDatabaseKey()
	deleted, err := databasePool.Delete(key)
	if deleted {
		if c := ash.logger.Check(zapcore.DebugLevel, "unloading unused CA database"); c != nil {
			c.Write(zap.String("db_key", key))
		}
	}
	if err != nil {
		if c := ash.logger.Check(zapcore.ErrorLevel, "closing CA database"); c != nil {
			c.Write(zap.String("db_key", key), zap.Error(err))
		}
	}
	return err
}

func (ash Handler) openDatabase() (*db.AuthDB, error) {
	key := ash.getDatabaseKey()
	database, loaded, err := databasePool.LoadOrNew(key, func() (caddy.Destructor, error) {
		dbFolder := filepath.Join(caddy.AppDataDir(), "acme_server", key)
		dbPath := filepath.Join(dbFolder, "db")

		err := os.MkdirAll(dbFolder, 0o755)
		if err != nil {
			return nil, fmt.Errorf("making folder for CA database: %v", err)
		}

		dbConfig := &db.Config{
			Type:       "bbolt",
			DataSource: dbPath,
		}
		database, err := db.New(dbConfig)
		return databaseCloser{&database}, err
	})

	if loaded {
		if c := ash.logger.Check(zapcore.DebugLevel, "loaded preexisting CA database"); c != nil {
			c.Write(zap.String("db_key", key))
		}
	}

	return database.(databaseCloser).DB, err
}

// makeClient creates an ACME client which will use a custom
// resolver instead of net.DefaultResolver.
func (ash Handler) makeClient() (acme.Client, error) {
	// If no local resolvers are configured, check for global resolvers from TLS app
	resolversToUse := ash.Resolvers
	if len(resolversToUse) == 0 {
		tlsAppIface, err := ash.ctx.App("tls")
		if err == nil {
			tlsApp := tlsAppIface.(*caddytls.TLS)
			if len(tlsApp.Resolvers) > 0 {
				resolversToUse = tlsApp.Resolvers
			}
		}
	}

	for _, v := range resolversToUse {
		addr, err := caddy.ParseNetworkAddressWithDefaults(v, "udp", 53)
		if err != nil {
			return nil, err
		}
		if addr.PortRangeSize() != 1 {
			return nil, fmt.Errorf("resolver address must have exactly one address; cannot call %v", addr)
		}
		ash.resolvers = append(ash.resolvers, addr)
	}

	var resolver *net.Resolver
	if len(ash.resolvers) != 0 {
		dialer := &net.Dialer{
			Timeout: 2 * time.Second,
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				//nolint:gosec
				addr := ash.resolvers[weakrand.IntN(len(ash.resolvers))]
				return dialer.DialContext(ctx, addr.Network, addr.JoinHostPort(0))
			},
		}
	} else {
		resolver = net.DefaultResolver
	}

	return resolverClient{
		Client:   acme.NewClient(),
		resolver: resolver,
		ctx:      ash.ctx,
	}, nil
}

type resolverClient struct {
	acme.Client

	resolver *net.Resolver
	ctx      context.Context
}

func (c resolverClient) LookupTxt(name string) ([]string, error) {
	return c.resolver.LookupTXT(c.ctx, name)
}

const defaultPathPrefix = "/acme/"

var (
	keyCleaner   = regexp.MustCompile(`[^\w.-_]`)
	databasePool = caddy.NewUsagePool()
)

type databaseCloser struct {
	DB *db.AuthDB
}

func (closer databaseCloser) Destruct() error {
	return (*closer.DB).Shutdown()
}

// Interface guards
var (
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddy.Provisioner           = (*Handler)(nil)
)
