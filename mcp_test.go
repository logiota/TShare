//go:build unix && !nomcp

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// talk runs the server over in-memory stdio and returns each response by id.
func talk(t *testing.T, m *mcpServer, lines ...string) map[string]map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := m.serve(strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("server wrote a non-JSON line: %q", l)
		}
		got[string(mustJSON(r["id"]))] = r
	}
	return got
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestMCPProtocol(t *testing.T) {
	got := talk(t, &mcpServer{defExpires: "1d"},
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":4,"method":"nope"}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"tshare_options","arguments":{"filter":"persist"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"share_stop","arguments":{"id":"--all"}}}`,
		`not json`,
	)
	if len(got) != 7 { // 6 requests + the parse error; the notification gets no reply
		t.Fatalf("got %d responses, want 7: %v", len(got), got)
	}
	init := got["1"]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-03-26" {
		t.Errorf("should echo a supported protocol version, got %v", init["protocolVersion"])
	}
	var names []string
	for _, tool := range got["2"]["result"].(map[string]any)["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "share_list,share_info,tshare_options,tshare_doctor,share_create,share_update,share_stop" {
		t.Errorf("tools = %v", names)
	}
	if got["4"]["error"].(map[string]any)["code"].(float64) != -32601 {
		t.Error("unknown method should be -32601")
	}
	if !strings.Contains(text(got["5"]), "--persist") {
		t.Errorf("tshare_options(persist) = %s", text(got["5"]))
	}
	if r := got["6"]["result"].(map[string]any); r["isError"] != true || !strings.Contains(text(got["6"]), "not a share id") {
		t.Errorf(`share_stop("--all") must be refused, got %v`, r)
	}
	if got["null"]["error"].(map[string]any)["code"].(float64) != -32700 {
		t.Error("garbage should be a -32700 parse error")
	}
}

func text(resp map[string]any) string {
	c := resp["result"].(map[string]any)["content"].([]any)
	return c[0].(map[string]any)["text"].(string)
}

func TestMCPReadOnly(t *testing.T) {
	got := talk(t, &mcpServer{readOnly: true},
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"share_create","arguments":{"path":"/tmp"}}}`)
	if n := len(got["1"]["result"].(map[string]any)["tools"].([]any)); n != 4 {
		t.Errorf("read-only lists %d tools, want 4", n)
	}
	if !strings.Contains(text(got["2"]), "read-only") {
		t.Errorf("read-only must refuse share_create: %s", text(got["2"]))
	}
}

func TestMCPCreateFences(t *testing.T) {
	allowed := t.TempDir()
	elsewhere := t.TempDir()
	site := filepath.Join(allowed, "site")
	app := filepath.Join(allowed, "app")
	os.MkdirAll(site, 0o755)
	os.MkdirAll(app, 0o755)
	os.WriteFile(filepath.Join(site, "index.html"), []byte("<h1>x</h1>"), 0o644)
	os.WriteFile(filepath.Join(app, "server.js"), []byte(`require("http").createServer(()=>{}).listen(1)`), 0o644)
	os.WriteFile(filepath.Join(elsewhere, "secret.txt"), []byte("x"), 0o644)
	real, _ := filepath.EvalSymlinks(allowed)
	m := &mcpServer{allow: []string{real}, defExpires: "1d"}

	refuse := map[string]mcpCreate{
		"outside --allow":         {Path: filepath.Join(elsewhere, "secret.txt")},
		"stdin":                   {Path: "-"},
		"no path":                 {},
		"missing file":            {Path: filepath.Join(allowed, "nope")},
		"runs code w/o allow-run": {Path: app, Website: true},
		"chooses a program":       {Path: site, ExtraArgs: []string{"--copyparty-bin", "/bin/sh"}},
		"yt-dlp raw args":         {Path: site, ExtraArgs: []string{"--yt-args", "--exec rm"}},
		"internal marker":         {Path: site, ExtraArgs: []string{"--__token", "x"}},
		"reserved launch flag":    {Path: site, ExtraArgs: []string{"--quiet"}},
		"positional smuggling":    {Path: site, ExtraArgs: []string{"/etc"}},
	}
	for name, req := range refuse {
		if argv, err := m.argv(req); err == nil {
			t.Errorf("%s: should be refused, got argv %v", name, argv)
		}
	}

	argv, err := m.argv(mcpCreate{Path: site, Website: true, Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(argv, " ")
	if !strings.HasPrefix(got, "host "+site) || !strings.Contains(got, "--expires 1d") || !strings.Contains(got, "--password pw") {
		t.Errorf("static site argv = %q (want tshare host, a default 1d expiry, the password)", got)
	}

	m.tailnetOnly, m.allowRun = true, true
	argv, err = m.argv(mcpCreate{Path: app, Website: true, Expires: "never"})
	if err != nil {
		t.Fatalf("--allow-run should permit an app: %v", err)
	}
	if got := strings.Join(argv, " "); !strings.Contains(got, "--tailnet") || !strings.Contains(got, "--expires never") {
		t.Errorf("--tailnet-only must be forced, and an explicit expiry kept: %q", got)
	}
}
