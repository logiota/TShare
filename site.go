//go:build unix

package main

import (
	"compress/gzip"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// --site: serve a folder as a live website, behaving like a modern static host
// (clean URLs, SPA routes, trailing-slash redirects, 404.html, gzip, caching).

// resolveSite validates the --site target and returns the web root + default
// document. A folder is served as-is; a single .html serves its parent folder.
func resolveSite(paths []string) (root, index string, err error) {
	if len(paths) != 1 {
		return "", "", errors.New("--site takes exactly one folder (or one .html file)")
	}
	abs, err := filepath.Abs(paths[0])
	if err != nil {
		return "", "", err
	}
	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return "", "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", "", err
	}
	if fi.IsDir() {
		return abs, "index.html", nil
	}
	if ext := strings.ToLower(filepath.Ext(abs)); ext != ".html" && ext != ".htm" {
		return "", "", errors.New("--site needs a folder or an .html file")
	}
	// a lone .html: serve its folder as the root (so sibling assets load)
	return filepath.Dir(abs), filepath.Base(abs), nil
}

// siteContentType returns an explicit, correct MIME type for web assets — vital
// because tshare sends X-Content-Type-Options: nosniff, so a wrong/empty type
// would make the browser refuse to run scripts/styles.
func siteContentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json", ".map":
		return "application/json; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".wasm":
		return "application/wasm"
	case ".webmanifest", ".manifest":
		return "application/manifest+json"
	case ".xml":
		return "application/xml; charset=utf-8"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".ico":
		return "image/x-icon"
	}
	return mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))
}

// serveSite routes a request within a --site share the way people expect a
// static host to behave:
//
//	/docs        → 301 to /docs/ (so relative links inside docs/index.html resolve)
//	/docs/       → docs/index.html (or a browsable listing if there's none)
//	/about       → about.html when there's no "about" (clean URLs)
//	/app/route   → index.html, for a browser navigation with no 404.html: a
//	               single-page app's client-side route (the Cloudflare Pages rule)
//	/missing.js  → 404.html if present, else a plain 404 — never HTML in place
//	               of an asset, which nosniff would turn into a confusing error
//
// Assets are served inline with correct types, cache validators, and gzip.
func (s *share) serveSite(w *respRec, r *http.Request, rel string) {
	root := s.roots[0].Abs
	abs, isDir, ok := s.confined(root, rel)
	if !ok && rel != "" && path.Ext(rel) == "" {
		abs, isDir, ok = s.confined(root, rel+".html") // clean URLs
	}
	if !ok {
		s.siteNotFound(w, r, root, rel)
		return
	}
	if isDir {
		if rel != "" && !strings.HasSuffix(r.URL.Path, "/") {
			// A RELATIVE Location, written by hand: the browser resolves it
			// against the URL it actually used, which is right under /<token>/,
			// at the root and on the LAN alike. (http.Redirect would make it
			// absolute from r.URL.Path — and under funnel tailscaled has already
			// stripped /<token>, so that would send visitors out of the share.)
			loc := path.Base(rel) + "/"
			if r.URL.RawQuery != "" {
				loc += "?" + r.URL.RawQuery
			}
			w.Header().Set("Location", loc)
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		idx := filepath.Join(abs, s.siteIndex)
		if !fileExists(idx) {
			idx = filepath.Join(abs, "index.htm")
		}
		if !fileExists(idx) {
			s.renderSiteList(w, rel, abs) // no index → browsable listing
			return
		}
		abs = idx
	}
	s.sendSiteFile(w, r, abs, http.StatusOK)
}

// siteNotFound answers a path with no file: the site's own 404.html if it has
// one, else — for a browser navigation to an extensionless path — the index, so
// single-page-app routes survive a reload or a shared deep link.
func (s *share) siteNotFound(w *respRec, r *http.Request, root, rel string) {
	if p := filepath.Join(root, "404.html"); fileExists(p) {
		s.sendSiteFile(w, r, p, http.StatusNotFound)
		return
	}
	if isNavigation(r) && path.Ext(rel) == "" {
		if idx := filepath.Join(root, s.siteIndex); fileExists(idx) {
			s.sendSiteFile(w, r, idx, http.StatusOK)
			return
		}
	}
	http.NotFound(w, r)
}

// isNavigation reports a browser page load, as opposed to fetch()/curl/assets.
func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if m := r.Header.Get("Sec-Fetch-Mode"); m != "" {
		return m == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// sendSiteFile serves one site file with an explicit type and cache validators
// (Last-Modified/ETag/304 via ServeContent), gzip-compressed when the client
// accepts it and the type benefits. status != 200 is for 404.html, which is
// written whole (no Range/304 dance for an error page).
func (s *share) sendSiteFile(w *respRec, r *http.Request, abs string, status int) {
	f, err := os.Open(abs)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	ct := siteContentType(abs)
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	var out http.ResponseWriter = w
	if compressible(ct) && fi.Size() >= 1024 {
		w.Header().Add("Vary", "Accept-Encoding")
		if acceptsGzip(r) && r.Header.Get("Range") == "" {
			gw := &gzipWriter{ResponseWriter: w}
			defer gw.Close()
			out = gw
		}
	}
	if status != http.StatusOK {
		out.WriteHeader(status)
		if r.Method != http.MethodHead {
			io.Copy(out, f)
		}
		return
	}
	http.ServeContent(out, r, filepath.Base(abs), fi.ModTime(), f)
}

// compressible reports whether a content type shrinks meaningfully under gzip.
// Images, audio, video, fonts and archives are already compressed.
func compressible(ct string) bool {
	ct, _, _ = strings.Cut(ct, ";")
	switch {
	case strings.HasPrefix(ct, "text/"):
		return true
	case ct == "application/json", ct == "application/javascript", ct == "application/xml",
		ct == "application/wasm", ct == "application/manifest+json", ct == "image/svg+xml":
		return true
	}
	return false
}

// acceptsGzip parses Accept-Encoding properly enough to honour "gzip;q=0".
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		enc, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if strings.EqualFold(enc, "gzip") || enc == "*" {
			return !strings.Contains(strings.ReplaceAll(params, " ", ""), "q=0")
		}
	}
	return false
}

var gzipPool = sync.Pool{New: func() any {
	gz, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
	return gz
}}

// gzipWriter compresses a response body only when it's a full 200: a 206 range,
// a 304 or an error passes through untouched, so ServeContent's Range and
// conditional-GET handling stays correct. Content-Length is dropped (the
// compressed size isn't known up front) and a strong ETag becomes weak, since
// the bytes on the wire no longer match it.
type gzipWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
	on          bool
}

func (g *gzipWriter) WriteHeader(code int) {
	if g.wroteHeader {
		return
	}
	g.wroteHeader = true
	if code == http.StatusOK && g.Header().Get("Content-Encoding") == "" {
		g.on = true
		h := g.Header()
		h.Del("Content-Length")
		h.Set("Content-Encoding", "gzip")
		if et := h.Get("ETag"); et != "" && !strings.HasPrefix(et, "W/") {
			h.Set("ETag", "W/"+et)
		}
	}
	g.ResponseWriter.WriteHeader(code)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if !g.on {
		return g.ResponseWriter.Write(b)
	}
	if g.gz == nil {
		g.gz = gzipPool.Get().(*gzip.Writer)
		g.gz.Reset(g.ResponseWriter)
	}
	return g.gz.Write(b)
}

func (g *gzipWriter) Close() {
	if g.gz != nil {
		g.gz.Close()
		gzipPool.Put(g.gz)
		g.gz = nil
	}
}
