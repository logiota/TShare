//go:build unix

package main

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Only tailscaled, arriving over loopback, is believed about who a visitor is.
// A direct connection naming itself a tailnet user must change nothing, or a
// stranger on the LAN could silence the "invalid access" alert and forge the
// address in the access log.
func TestCallerBelievesOnlyTailscaled(t *testing.T) {
	req := func(remote string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-For", "100.64.0.9")
		r.Header.Set("Tailscale-User-Login", "alice@example.com")
		return r
	}
	s := &share{cfg: defaultConfig()}
	if who, authed, proxied := s.caller(req("127.0.0.1:5000")); !proxied || !authed || who != "100.64.0.9 (alice@example.com)" {
		t.Errorf("via tailscaled: who=%q authed=%v proxied=%v", who, authed, proxied)
	}
	if who, authed, proxied := s.caller(req("192.168.1.50:5000")); proxied || authed || who != "192.168.1.50:5000" {
		t.Errorf("a LAN peer forged its identity: who=%q authed=%v proxied=%v", who, authed, proxied)
	}
	s.cfg.Local = true // --local: nothing is proxied, not even loopback
	if who, authed, proxied := s.caller(req("127.0.0.1:5000")); proxied || authed || who != "127.0.0.1:5000" {
		t.Errorf("--local must ignore the headers: who=%q authed=%v proxied=%v", who, authed, proxied)
	}
}

func TestSanitizeName(t *testing.T) {
	for in, want := range map[string]string{
		"report.pdf":       "report.pdf",
		"../../etc/passwd": "passwd",
		`C:\Users\x\a.txt`: "a.txt",
		".envrc":           "envrc", // listings hide dotfiles: never accept one
		"..hidden":         "hidden",
		". .x":             "x",
		"__upload":         "_upload", // can no longer collide with the endpoint
		"a\x00b\nc.txt":    "abc.txt",
		"..":               "",
		".":                "",
		"/":                "",
	} {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestUploadCantPlantAHiddenFile(t *testing.T) {
	dir := t.TempDir()
	c := defaultConfig()
	c.Quiet, c.NoNotify, c.Local = true, true, true
	s := &share{cfg: c, mode: "inbox", token: "tok", upDir: dir, maxUp: 1 << 20,
		roots: []rootEnt{{Name: "inbox", Abs: dir, IsDir: true}}, shutdown: make(chan string, 1)}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, _ := mw.CreateFormFile("f", ".envrc")
	fw.Write([]byte("export EVIL=1"))
	mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/tok/__upload", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.RemoteAddr = "192.0.2.7:4321"
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("upload: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(dir, ".envrc")); err == nil {
		t.Fatal("an upload created a hidden file")
	}
	fi, err := os.Stat(filepath.Join(dir, "envrc"))
	if err != nil {
		t.Fatalf("the upload should land as a visible file: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("received files are the owner's alone: mode %v, want 0600", fi.Mode().Perm())
	}
}

// A yt-dlp share is live before its file exists. The finished download is
// handed over through ytPend, never written into s.roots (which requests read
// without a lock) — run with -race, this is what guards that.
func TestFileShareAdoptsFinishedDownload(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real name.m4a")
	os.WriteFile(real, []byte("audio-bytes"), 0o644)
	c := defaultConfig()
	c.Quiet, c.NoNotify, c.Local = true, true, true
	s := &share{cfg: c, mode: "file", token: "tok", ytPend: &ytPending{}, shutdown: make(chan string, 1),
		roots: []rootEnt{{Name: "guess.mp4", Abs: filepath.Join(dir, "guess.mp4")}}}
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/tok/guess.mp4?raw=1", nil)
		req.RemoteAddr = "192.0.2.7:4321"
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec
	}
	if rec := get(); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("while downloading: got %d, want 503", rec.Code)
	}
	done := make(chan struct{})
	go func() { // readers racing the hand-over
		defer close(done)
		for i := 0; i < 200; i++ {
			get()
			_ = s.describe()
			_ = s.title()
		}
	}()
	s.ytPend.set(50)
	s.ytPend.finish(rootEnt{Name: "real name.m4a", Abs: real, Size: 11}, nil)
	<-done
	if rec := get(); rec.Code != 200 || rec.Body.String() != "audio-bytes" {
		t.Fatalf("after the download: %d %q", rec.Code, rec.Body.String())
	}
	if s.file().Name != "real name.m4a" || s.roots[0].Name != "guess.mp4" {
		t.Errorf("file() should return the finished download and leave roots alone: %q / %q", s.file().Name, s.roots[0].Name)
	}
	failed := &share{cfg: c, mode: "file", token: "tok", ytPend: &ytPending{}, shutdown: make(chan string, 1),
		roots: s.roots}
	failed.ytPend.finish(rootEnt{}, os.ErrNotExist)
	s = failed
	if rec := get(); rec.Code != http.StatusBadGateway {
		t.Errorf("a failed download: got %d, want 502", rec.Code)
	}
}
