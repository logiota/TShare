//go:build unix

package main

// Tests for the core alone: they use nothing outside main.go, so `go test`
// works in a main.go-only build too.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinEngine(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	os.WriteFile(filepath.Join(root, "readme.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(root, ".env"), []byte("SECRET"), 0o644)
	os.WriteFile(filepath.Join(outside, "x.txt"), []byte("outside"), 0o644)
	os.Symlink(outside, filepath.Join(root, "escape"))
	root, _ = filepath.EvalSymlinks(root)

	h := builtinHandler(root, true, "tok", "pw", true)
	get := func(p string, auth bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		if auth {
			req.SetBasicAuth("", "pw")
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := get("/tok/readme.txt", true); rec.Code != 200 || rec.Body.String() != "hello" {
		t.Errorf("file: %d %q", rec.Code, rec.Body.String())
	}
	if rec := get("/tok/", true); !strings.Contains(rec.Body.String(), "readme.txt") || strings.Contains(rec.Body.String(), ".env") {
		t.Errorf("listing must show files and hide dotfiles: %s", rec.Body.String())
	}
	if rec := get("/tok/sub", true); rec.Code != 301 || rec.Header().Get("Location") != "sub/" {
		t.Errorf("a folder without its slash should redirect relatively: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	for name, p := range map[string]string{
		"no token on a direct hit": "/readme.txt",
		"dotfile":                  "/tok/.env",
		"symlink out of the share": "/tok/escape/x.txt",
		"traversal":                "/tok/../../" + filepath.Base(outside) + "/x.txt",
	} {
		if rec := get(p, true); rec.Code != 404 {
			t.Errorf("%s: got %d, want 404", name, rec.Code)
		}
	}
	if rec := get("/tok/readme.txt", false); rec.Code != 401 {
		t.Errorf("no password: got %d, want 401", rec.Code)
	}
	if rec := get("/tok/readme.txt", true); rec.Header().Get("Content-Security-Policy") != "sandbox" {
		t.Error("served files must be sandboxed")
	}

	file := builtinHandler(filepath.Join(root, "readme.txt"), false, "tok", "", false)
	rec := httptest.NewRecorder()
	file.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/anything", nil)) // as tailscaled delivers it
	if rec.Body.String() != "hello" {
		t.Errorf("a file share serves its file at any path: %q", rec.Body.String())
	}
}

func TestCoreShareControl(t *testing.T) {
	for _, id := range []string{"all", "--all", "-a", "", "../x", "a b"} {
		if err := stopShare(id); err == nil {
			t.Errorf("stopShare(%q) must refuse", id)
		}
	}
	got := strings.Join(insertArgs([]string{"-p", "x", "file"}, "-b"), " ")
	if got != "-b -p x file" {
		t.Errorf("insertArgs on a bare share = %q", got)
	}
	if expandHome("~/x") == "~/x" {
		t.Error("expandHome should expand ~/")
	}
}
