// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/openbao/openbao/sdk/v2/helper/consts"
	"github.com/openbao/openbao/sdk/v2/helper/template"
	"github.com/openbao/openbao/sdk/v2/logical"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var StdAllowedHeaders = []string{
	"Content-Type",
	"Authorization",
	consts.AuthHeaderName,
	consts.MFAHeaderName,
	consts.NoRequestForwardingHeaderName,
	consts.WrapFormatHeaderName,
	consts.WrapTTLHeaderName,
	"X-Requested-With",
	"X-Vault-AWS-IAM-Server-ID",
	"X-Vault-Policy-Override",
}

// CORSConfig stores the state of the CORS configuration.
type CORSConfig struct {
	sync.RWMutex     `json:"-"`
	core             *Core
	Enabled          *uint32  `json:"enabled"`
	AllowedOrigins   []string `json:"allowed_origins,omitempty"`
	AllowedHeaders   []string `json:"allowed_headers,omitempty"`
	AllowCredentials bool     `json:"allow_credentials,omitempty"`
}

func (c *Core) saveCORSConfig(ctx context.Context) error {
	enabled := atomic.LoadUint32(c.corsConfig.Enabled)
	localConfig := &CORSConfig{
		Enabled: &enabled,
	}

	c.corsConfig.RLock()
	localConfig.AllowedOrigins = c.corsConfig.AllowedOrigins
	localConfig.AllowedHeaders = c.corsConfig.AllowedHeaders
	localConfig.AllowCredentials = c.corsConfig.AllowCredentials
	c.corsConfig.RUnlock()

	entry, err := logical.StorageEntryJSON("config/cors", localConfig)
	if err != nil {
		return fmt.Errorf("failed to create CORS config entry: %w", err)
	}

	if err := c.systemBarrierView.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to save CORS config: %w", err)
	}

	return nil
}

// This should only be called with the core state lock held for writing
func (c *Core) loadCORSConfig(ctx context.Context) error {
	// Load the config in
	out, err := c.systemBarrierView.Get(ctx, "config/cors")
	if err != nil {
		return fmt.Errorf("failed to read CORS config: %w", err)
	}
	if out == nil {
		return nil
	}

	config := new(CORSConfig)
	if err = out.DecodeJSON(config); err != nil {
		return err
	}

	if config.Enabled == nil {
		config.Enabled = new(uint32)
	}

	config.core = c
	c.corsConfig = config

	return nil
}

// Enable takes either a '*' or a comma-separated list of URLs that can make
// cross-origin requests to Vault.
func (c *CORSConfig) Enable(ctx context.Context, urls []string, headers []string, allow_credentials bool) error {
	if len(urls) == 0 {
		return errors.New("at least one origin or the wildcard must be provided")
	}

	if slices.Contains(urls, "*") && len(urls) > 1 {
		return errors.New("to allow all origins the '*' must be the only value for allowed_origins")
	}

	c.Lock()
	c.AllowedOrigins = urls

	// Start with the standard headers to Vault accepts.
	c.AllowedHeaders = append([]string{}, StdAllowedHeaders...)

	// Whether to return the "Access-Control-Allow-Credentials: true" header
	c.AllowCredentials = allow_credentials

	// Allow the user to add additional headers to the list of
	// headers allowed on cross-origin requests.
	if len(headers) > 0 {
		c.AllowedHeaders = append(c.AllowedHeaders, headers...)
	}
	c.Unlock()

	// as true
	atomic.StoreUint32(c.Enabled, 1)

	return c.core.saveCORSConfig(ctx)
}

// IsEnabled returns the value of CORSConfig.Enabled as bool.
func (c *CORSConfig) IsEnabled() bool {
	return atomic.LoadUint32(c.Enabled) == 1
}

// Disable sets CORS to disabled and clears the allowed origins & headers.
func (c *CORSConfig) Disable(ctx context.Context) error {
	// as false
	atomic.StoreUint32(c.Enabled, 0)
	c.Lock()

	c.AllowedOrigins = nil
	c.AllowedHeaders = nil
	c.AllowCredentials = false

	c.Unlock()

	return c.core.saveCORSConfig(ctx)
}

// IsValidOrigin determines if the origin of the request is allowed to make
// cross-origin requests based on the CORSConfig.
func (c *CORSConfig) IsValidOrigin(origin string) bool {
	// If we aren't enabling CORS then all origins are valid
	if !c.IsEnabled() {
		return true
	}

	c.RLock()
	defer c.RUnlock()

	if len(c.AllowedOrigins) == 0 {
		return false
	}

	if len(c.AllowedOrigins) == 1 && (c.AllowedOrigins)[0] == "*" {
		return true
	}

	return slices.Contains(c.AllowedOrigins, origin)
}

func (fsrv *FileServer) serveBrowse(fileSystem fs.FS, root, dirPath string, w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if c := fsrv.logger.Check(zapcore.DebugLevel, "browse enabled; listing directory contents"); c != nil {
		c.Write(zap.String("path", dirPath), zap.String("root", root))
	}

	// Navigation on the client-side gets messed up if the
	// URL doesn't end in a trailing slash because hrefs to
	// "b/c" at path "/a" end up going to "/b/c" instead
	// of "/a/b/c" - so we have to redirect in this case
	// so that the path is "/a/" and the client constructs
	// relative hrefs "b/c" to be "/a/b/c".

	originalRequest := r.Context().Value(caddyhttp.OriginalRequestCtxKey).(http.Request)
	if r.URL.Path == "" || path.Base(originalRequest.URL.Path) == path.Base(r.URL.Path) {
		if !strings.HasSuffix(originalRequest.URL.Path, "/") {
			if c := fsrv.logger.Check(zapcore.DebugLevel, "redirecting to trailing slash to preserve hrefs"); c != nil {
				c.Write(zap.String("request_path", r.URL.Path))
			}
			return redirect(w, r, originalRequest.URL.Path+"/")
		}
	}

	dir, err := fsrv.openFile(fileSystem, dirPath, w)
	if err != nil {
		return err
	}
	defer dir.Close()

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// TODO: not entirely sure if path.Clean() is necessary here but seems like a safe plan (i.e. /%2e%2e%2f) - someone could verify this
	listing, err := fsrv.loadDirectoryContents(r.Context(), fileSystem, dir.(fs.ReadDirFile), root, path.Clean(r.URL.EscapedPath()), repl)
	switch {
	case errors.Is(err, fs.ErrPermission):
		return caddyhttp.Error(http.StatusForbidden, err)
	case errors.Is(err, fs.ErrNotExist):
		return fsrv.notFound(w, r, next)
	case err != nil:
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.Header().Add("Vary", "Accept, Accept-Encoding")

	// speed up browser/client experience and caching by supporting If-Modified-Since
	if ifModSinceStr := r.Header.Get("If-Modified-Since"); ifModSinceStr != "" {
		// basically a copy of stdlib file server's handling of If-Modified-Since
		ifModSince, err := http.ParseTime(ifModSinceStr)
		if err == nil && listing.lastModified.Truncate(time.Second).Compare(ifModSince) <= 0 {
			w.WriteHeader(http.StatusNotModified)
			return nil
		}
	}

	fsrv.browseApplyQueryParams(w, r, listing)

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	acptHdr := strings.ToLower(strings.Join(r.Header["Accept"], ","))
	w.Header().Set("Last-Modified", listing.lastModified.Format(http.TimeFormat))

	switch {
	case strings.Contains(acptHdr, "application/json"):
		if err := json.NewEncoder(buf).Encode(listing.Items); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

	case strings.Contains(acptHdr, "text/plain"):
		writer := tabwriter.NewWriter(buf, 0, 8, 1, '\t', tabwriter.AlignRight)

		// Header on top
		if _, err := fmt.Fprintln(writer, "Name\tSize\tModified"); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}

		// Lines to separate the header
		if _, err := fmt.Fprintln(writer, "----\t----\t--------"); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}

		// Actual files
		for _, item := range listing.Items {
			//nolint:gosec // not sure how this could be XSS unless you lose control of the file system (like aren't sanitizing) and client ignores Content-Type of text/plain
			if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\n",
				item.Name, item.HumanSize(), item.HumanModTime("January 2, 2006 at 15:04:05"),
			); err != nil {
				return caddyhttp.Error(http.StatusInternalServerError, err)
			}
		}

		if err := writer.Flush(); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	default:
		var fs http.FileSystem
		if fsrv.Root != "" {
			fs = http.Dir(repl.ReplaceAll(fsrv.Root, "."))
		}

		tplCtx := &templateContext{
			TemplateContext: templates.TemplateContext{
				Root:       fs,
				Req:        r,
				RespHeader: templates.WrappedHeader{Header: w.Header()},
			},
			browseTemplateContext: listing,
		}

		tpl, err := fsrv.makeBrowseTemplate(tplCtx)
		if err != nil {
			return fmt.Errorf("parsing browse template: %v", err)
		}
		if err := tpl.Execute(buf, tplCtx); err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}

	_, _ = buf.WriteTo(w)

	return nil
}

func (fsrv *FileServer) loadDirectoryContents(ctx context.Context, fileSystem fs.FS, dir fs.ReadDirFile, root, urlPath string, repl *caddy.Replacer) (*browseTemplateContext, error) {
	// modTime for the directory itself
	stat, err := dir.Stat()
	if err != nil {
		return nil, err
	}
	dirLimit := defaultDirEntryLimit
	if fsrv.Browse.FileLimit != 0 {
		dirLimit = fsrv.Browse.FileLimit
	}
	files, err := dir.ReadDir(dirLimit)
	if err != nil && err != io.EOF {
		return nil, err
	}

	// user can presumably browse "up" to parent folder if path is longer than "/"
	canGoUp := len(urlPath) > 1

	return fsrv.directoryListing(ctx, fileSystem, stat.ModTime(), files, canGoUp, root, urlPath, repl), nil
}

// browseApplyQueryParams applies query parameters to the listing.
// It mutates the listing and may set cookies.
func (fsrv *FileServer) browseApplyQueryParams(w http.ResponseWriter, r *http.Request, listing *browseTemplateContext) {
	var orderParam, sortParam string

	// The configs in Caddyfile have lower priority than Query params,
	// so put it at first.
	for idx, entry := range fsrv.Browse.SortOptions {
		// Only `sort` & `order`, 2 params are allowed
		if idx >= 2 {
			break
		}
		switch entry {
		case sortByName, sortByNameDirFirst, sortBySize, sortByTime:
			sortParam = entry
		case sortOrderAsc, sortOrderDesc:
			orderParam = entry
		}
	}

	layoutParam := r.URL.Query().Get("layout")
	limitParam := r.URL.Query().Get("limit")
	offsetParam := r.URL.Query().Get("offset")
	sortParamTmp := r.URL.Query().Get("sort")
	if sortParamTmp != "" {
		sortParam = sortParamTmp
	}
	orderParamTmp := r.URL.Query().Get("order")
	if orderParamTmp != "" {
		orderParam = orderParamTmp
	}

	switch layoutParam {
	case "list", "grid", "":
		listing.Layout = layoutParam
	default:
		listing.Layout = "list"
	}

	// figure out what to sort by
	switch sortParam {
	case "":
		sortParam = sortByNameDirFirst
		if sortCookie, sortErr := r.Cookie("sort"); sortErr == nil {
			sortParam = sortCookie.Value
		}
	case sortByName, sortByNameDirFirst, sortBySize, sortByTime:
		http.SetCookie(w, &http.Cookie{Name: "sort", Value: sortParam, Secure: r.TLS != nil})
	}

	// then figure out the order
	switch orderParam {
	case "":
		orderParam = sortOrderAsc
		if orderCookie, orderErr := r.Cookie("order"); orderErr == nil {
			orderParam = orderCookie.Value
		}
	case sortOrderAsc, sortOrderDesc:
		http.SetCookie(w, &http.Cookie{Name: "order", Value: orderParam, Secure: r.TLS != nil})
	}

	// finally, apply the sorting and limiting
	listing.applySortAndLimit(sortParam, orderParam, limitParam, offsetParam)
}

// makeBrowseTemplate creates the template to be used for directory listings.
func (fsrv *FileServer) makeBrowseTemplate(tplCtx *templateContext) (*template.Template, error) {
	var tpl *template.Template
	var err error

	if fsrv.Browse.TemplateFile != "" {
		tpl = tplCtx.NewTemplate(path.Base(fsrv.Browse.TemplateFile))
		tpl, err = tpl.ParseFiles(fsrv.Browse.TemplateFile)
		if err != nil {
			return nil, fmt.Errorf("parsing browse template file: %v", err)
		}
	} else {
		tpl = tplCtx.NewTemplate("default_listing")
		tpl, err = tpl.Parse(BrowseTemplate)
		if err != nil {
			return nil, fmt.Errorf("parsing default browse template: %v", err)
		}
	}

	return tpl, nil
}

// isSymlinkTargetDir returns true if f's symbolic link target
// is a directory.
func (fsrv *FileServer) isSymlinkTargetDir(fileSystem fs.FS, f fs.FileInfo, root, urlPath string) bool {
	if !isSymlink(f) {
		return false
	}
	target := caddyhttp.SanitizedPathJoin(root, path.Join(urlPath, f.Name()))
	targetInfo, err := fs.Stat(fileSystem, target)
	if err != nil {
		return false
	}
	return targetInfo.IsDir()
}

// isSymlink return true if f is a symbolic link.
func isSymlink(f fs.FileInfo) bool {
	return f.Mode()&os.ModeSymlink != 0
}

// templateContext powers the context used when evaluating the browse template.
// It combines browse-specific features with the standard templates handler
// features.
type templateContext struct {
	templates.TemplateContext
	*browseTemplateContext
}

// bufPool is used to increase the efficiency of file listings.
var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}
