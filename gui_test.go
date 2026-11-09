//go:build unix && !nogui

package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testGUI() *guiServer {
	return &guiServer{secret: "s3cr3t", hosts: map[string]bool{"127.0.0.1:9": true},
		origins: map[string]bool{"http://127.0.0.1:9": true}, dashPW: map[string]string{}}
}

func guiDo(g *guiServer, method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:9"
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Host" {
			req.Host = hdr[i+1]
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, req)
	return rec
}

var guiJSON = []string{"X-Tshare-GUI", "1", "Content-Type", "application/json"}

// The GUI can publish files, so a web page the user visits must not be able to
// drive it: wrong secret, a rebinding Host, a plain form post, a foreign Origin.
func TestGUIRefusesOutsiders(t *testing.T) {
	g := testGUI()
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"no secret":         guiDo(g, "GET", "/api/state", ""),
		"wrong secret":      guiDo(g, "GET", "/nope/api/state", ""),
		"rebinding Host":    guiDo(g, "GET", "/s3cr3t/api/state", "", "Host", "evil.example"),
		"form post (CSRF)":  guiDo(g, "POST", "/s3cr3t/api/stop", "ID=x", "Content-Type", "application/x-www-form-urlencoded"),
		"no custom header":  guiDo(g, "POST", "/s3cr3t/api/stop", `{}`, "Content-Type", "application/json"),
		"foreign Origin":    guiDo(g, "POST", "/s3cr3t/api/stop", `{}`, append(guiJSON, "Origin", "https://evil.example")...),
		"unexpected method": guiDo(g, "DELETE", "/s3cr3t/api/stop", ""),
	} {
		if rec.Code < 400 {
			t.Errorf("%s: got %d, want a refusal", name, rec.Code)
		}
	}
	page := guiDo(g, "GET", "/s3cr3t/", "")
	csp := page.Header().Get("Content-Security-Policy")
	if page.Code != 200 || !strings.Contains(csp, "script-src 'nonce-") || page.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("page: %d, CSP %q", page.Code, csp)
	}
	if strings.Contains(page.Body.String(), "{{NONCE}}") {
		t.Error("the page's script nonce was never filled in")
	}
}

func TestGUIComposesAndRefusesBadIDs(t *testing.T) {
	g := testGUI()
	site := t.TempDir()
	os.WriteFile(filepath.Join(site, "index.html"), []byte("<h1>x</h1>"), 0o644)
	body, _ := json.Marshal(map[string]any{"Target": site, "Opts": map[string]any{"root": true, "password": "pw", "persist": true}})
	rec := guiDo(g, "POST", "/s3cr3t/api/compose", string(body), guiJSON...)
	var r map[string]any
	json.Unmarshal(rec.Body.Bytes(), &r)
	if r["stack"] != "static" || r["host"] != true || !strings.Contains(r["preview"].(string), "--root") ||
		strings.Contains(r["preview"].(string), "pw ") {
		t.Errorf("compose = %v", r)
	}
	rec = guiDo(g, "POST", "/s3cr3t/api/compose", `{"Opts":{"quiet":true}}`, guiJSON...)
	if !strings.Contains(rec.Body.String(), "can't be set") {
		t.Errorf("a reserved launch flag must be refused: %s", rec.Body.String())
	}
	for _, id := range []string{"all", "--all", "-a", ""} {
		rec = guiDo(g, "POST", "/s3cr3t/api/stop", `{"ID":"`+id+`"}`, guiJSON...)
		if !strings.Contains(rec.Body.String(), "error") {
			t.Errorf("stop %q must be refused, got %s", id, rec.Body.String())
		}
	}
	var cat map[string]any
	json.Unmarshal(guiDo(g, "GET", "/s3cr3t/api/catalog", "").Body.Bytes(), &cat)
	for _, o := range cat["options"].([]any) {
		if n := o.(map[string]any)["Name"].(string); reservedFlags[n] {
			t.Errorf("the catalogue offers --%s, which the GUI sets itself", n)
		}
	}
}
