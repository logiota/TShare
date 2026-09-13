//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// `tshare host` runs what it detects, so the .js check must separate a server
// we should RUN from a browser asset we must only SERVE — and a server should
// win over a sibling index.html, since it can serve that page itself.
func TestDetectStackJS(t *testing.T) {
	cases := []struct {
		name     string
		files    map[string]string
		wantKind string
	}{
		{"browser js with .listen( beside index.html", map[string]string{
			"app.js":     `socket.listen("msg", () => {});`,
			"index.html": `<h1>x</h1>`,
		}, "static"},
		{"plain browser js beside index.html", map[string]string{
			"app.js":     `document.querySelector("a");`,
			"index.html": `<h1>x</h1>`,
		}, "static"},
		{"node server, no index.html", map[string]string{
			"server.js": `const http=require("node:http");http.createServer(()=>{}).listen(3000);`,
		}, "node (server.js)"},
		{"express server wins over index.html", map[string]string{
			"server.js":  `const e=require("express");e().listen(3000);`,
			"index.html": `<h1>x</h1>`,
		}, "node (server.js)"},
		{"Bun.serve", map[string]string{
			"app.js": `Bun.serve({fetch(){}});`,
		}, "node (app.js)"},
		{"conventional entry preferred over other servers", map[string]string{
			"zebra.js":  `const http=require("http");http.createServer(()=>{}).listen(1);`,
			"server.js": `const http=require("http");http.createServer(()=>{}).listen(2);`,
		}, "node (server.js)"},
		{"package.json still wins", map[string]string{
			"package.json": `{"scripts":{"start":"node x.js"}}`,
			"server.js":    `require("http").createServer(()=>{}).listen(1);`,
		}, "node (npm start)"},
		{"nothing runnable", map[string]string{"readme.md": "hi"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for n, body := range tc.files {
				if err := os.WriteFile(filepath.Join(dir, n), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, kind := detectStack(dir); kind != tc.wantKind {
				t.Errorf("detectStack = %q, want %q", kind, tc.wantKind)
			}
		})
	}
}
