//go:build unix

package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// siteShare builds a --site share over a fixture folder, reached the way a
// direct LAN visitor reaches it: /<token>/… from a non-loopback address.
func siteShare(t *testing.T, root bool) (*share, string) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"index.html":      "<!doctype html>INDEX",
		"about.html":      "<!doctype html>ABOUT",
		"docs/index.html": "<!doctype html>DOCS",
		"app.js":          strings.Repeat("console.log('tshare');\n", 200),
		"style.css":       "body{}",
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dir, _ = filepath.EvalSymlinks(dir)
	c := defaultConfig()
	c.Quiet, c.NoNotify, c.Root, c.Site = true, true, root, true
	s := &share{cfg: c, mode: "site", token: "tok", siteIndex: "index.html",
		roots: []rootEnt{{Name: "site", Abs: dir, IsDir: true}}, shutdown: make(chan string, 1)}
	return s, dir
}

func get(s *share, path string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = "192.0.2.7:4321" // direct, not via tailscaled
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

var nav = []string{"Accept", "text/html", "Sec-Fetch-Mode", "navigate"}

func TestSiteBehavesLikeAStaticHost(t *testing.T) {
	s, dir := siteShare(t, false)
	check := func(name string, rec *httptest.ResponseRecorder, code int, body string) {
		t.Helper()
		if rec.Code != code || !strings.Contains(rec.Body.String(), body) {
			t.Errorf("%s: got %d %q, want %d containing %q", name, rec.Code, trim(rec.Body.String()), code, body)
		}
	}
	check("index", get(s, "/tok/"), 200, "INDEX")
	check("clean URL", get(s, "/tok/about"), 200, "ABOUT")
	check("dir with slash", get(s, "/tok/docs/"), 200, "DOCS")
	check("SPA route (browser)", get(s, "/tok/app/settings", nav...), 200, "INDEX")
	check("SPA route (fetch) is a 404", get(s, "/tok/app/settings"), 404, "")
	check("missing asset never gets HTML", get(s, "/tok/missing.js", nav...), 404, "")

	// The Location must stay RELATIVE. Under funnel, tailscaled strips /<token>
	// before we see the path, so an absolute "/docs/" would leave the share.
	proxied := httptest.NewRequest(http.MethodGet, "/docs?x=1", nil) // as tailscaled delivers it
	proxied.RemoteAddr = "127.0.0.1:5555"
	for _, req := range []*http.Request{proxied, httptest.NewRequest(http.MethodGet, "/tok/docs?x=1", nil)} {
		if req.RemoteAddr == "" || !strings.HasPrefix(req.RemoteAddr, "127.") {
			req.RemoteAddr = "192.0.2.7:4321"
		}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if rec.Code != 301 || rec.Header().Get("Location") != "docs/?x=1" {
			t.Errorf("%s: dir without slash got %d → %q, want 301 → docs/?x=1", req.URL.Path, rec.Code, rec.Header().Get("Location"))
		}
	}

	os.WriteFile(filepath.Join(dir, "404.html"), []byte("<!doctype html>CUSTOM404"), 0o644)
	check("404.html wins over SPA", get(s, "/tok/nope", nav...), 404, "CUSTOM404")
}

func TestSiteGzip(t *testing.T) {
	s, dir := siteShare(t, false)
	want, _ := os.ReadFile(filepath.Join(dir, "app.js"))

	rec := get(s, "/tok/app.js", "Accept-Encoding", "gzip")
	if rec.Header().Get("Content-Encoding") != "gzip" || rec.Header().Get("Content-Length") != "" {
		t.Fatalf("expected gzip without a length, got %v", rec.Header())
	}
	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(zr)
	if string(got) != string(want) {
		t.Fatal("gzip body doesn't decompress to the file")
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
		t.Error("compressible responses must Vary on Accept-Encoding")
	}

	if rec := get(s, "/tok/app.js", "Accept-Encoding", "gzip", "Range", "bytes=0-9"); rec.Code != 206 || rec.Header().Get("Content-Encoding") != "" {
		t.Errorf("a range request must stay identity: %d %v", rec.Code, rec.Header().Get("Content-Encoding"))
	}
	if rec := get(s, "/tok/app.js", "Accept-Encoding", "gzip;q=0"); rec.Header().Get("Content-Encoding") != "" {
		t.Error("gzip;q=0 means no gzip")
	}
	if rec := get(s, "/tok/style.css", "Accept-Encoding", "gzip"); rec.Header().Get("Content-Encoding") != "" {
		t.Error("tiny files aren't worth compressing")
	}
}

// --root has no secret path: a direct hit needs no token. Without it, a
// direct hit without the token must stay a 404.
func TestRootGate(t *testing.T) {
	plain, _ := siteShare(t, false)
	if rec := get(plain, "/style.css"); rec.Code != 404 {
		t.Errorf("token-less direct hit on a normal share: got %d, want 404", rec.Code)
	}
	root, _ := siteShare(t, true)
	if rec := get(root, "/style.css"); rec.Code != 200 {
		t.Errorf("--root share: /style.css got %d, want 200", rec.Code)
	}
	if rec := get(root, "/about"); !strings.Contains(rec.Body.String(), "ABOUT") {
		t.Errorf("--root share: clean URL at the root failed: %q", trim(rec.Body.String()))
	}
}

func trim(s string) string {
	if len(s) > 60 {
		return s[:60] + "…"
	}
	return s
}
