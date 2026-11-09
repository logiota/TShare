//go:build unix && !nomcp

package main

// `tshare mcp`: a Model Context Protocol server, so an AI agent (Claude Code,
// Claude Desktop, any MCP client) can share files, publish websites, and list,
// change and stop shares. JSON-RPC 2.0 over stdio, stdlib only. Shares launch
// detached (control.go), so they outlive the agent's session.
// Optional — build with -tags nomcp to leave it out.
//
// An agent can be talked into things (a hostile web page, a poisoned file), and
// this one can publish your files to the internet, so its defaults are careful:
//   - shares it creates expire in a day unless it asks for longer;
//   - --allow <dir> fences what it may share (default: anything you can read);
//   - --tailnet-only keeps every share off the public internet;
//   - --read-only exposes only the listing tools;
//   - running a folder's own code (an app found by `tshare host`) needs
//     --allow-run, and flags that name a program to execute are refused.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func init() { register(cmdMCP, "mcp") }

type mcpServer struct {
	allow       []string // resolved roots an agent may share from (empty = anything)
	tailnetOnly bool
	readOnly    bool
	allowRun    bool
	defExpires  string
}

// mcpDeniedFlags name a program to execute or pass raw arguments to one — a
// remote caller must not choose what runs on this machine.
var mcpDeniedFlags = map[string]bool{
	"copyparty-bin": true, "copyparty-args": true, "tailscale-bin": true,
	"yt-args": true, "dir": true, "profile": true, "template": true, "no-config": true,
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdMCP(args []string) {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	var allow stringList
	fs.Var(&allow, "allow", "only share files under this directory (repeatable)")
	tailnet := fs.Bool("tailnet-only", false, "every share is tailnet-only, never public")
	readOnly := fs.Bool("read-only", false, "expose only list/info/options/doctor — no creating or stopping")
	allowRun := fs.Bool("allow-run", false, "let `website` start an app found in a folder (npm start, python …)")
	expires := fs.String("default-expires", "1d", "expiry for agent-made shares that don't set one")
	fs.Parse(args)

	m := &mcpServer{tailnetOnly: *tailnet, readOnly: *readOnly, allowRun: *allowRun, defExpires: *expires}
	for _, d := range allow {
		real, err := filepath.EvalSymlinks(expandHome(d))
		if err != nil {
			log.Fatalf("tshare mcp: --allow %s: %v", d, err)
		}
		m.allow = append(m.allow, real)
	}
	// stdout carries the protocol and nothing else; logs go to stderr
	log.SetOutput(os.Stderr)
	if err := m.serve(os.Stdin, os.Stdout); err != nil {
		log.Fatalf("tshare mcp: %v", err)
	}
}

// ---------------------------------------------------------------------------
// JSON-RPC over stdio: one message per line

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var mcpVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

func (m *mcpServer) serve(in io.Reader, out io.Writer) error {
	var mu sync.Mutex
	send := func(id json.RawMessage, result any, e *rpcErr) {
		resp := map[string]any{"jsonrpc": "2.0", "id": id}
		if e != nil {
			resp["error"] = e
		} else {
			resp["result"] = result
		}
		b, _ := json.Marshal(resp)
		mu.Lock()
		out.Write(append(b, '\n'))
		mu.Unlock()
	}
	var wg sync.WaitGroup
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var msg rpcMsg
		if err := json.Unmarshal(line, &msg); err != nil || msg.JSONRPC != "2.0" {
			send(json.RawMessage("null"), nil, &rpcErr{-32700, "parse error: expected one JSON-RPC 2.0 message per line"})
			continue
		}
		if msg.Method == "" {
			continue // a response to a request we never send
		}
		note := len(msg.ID) == 0 || string(msg.ID) == "null"
		if msg.Method == "tools/call" && !note {
			// a launch can take a while; keep answering pings meanwhile
			wg.Add(1)
			go func(msg rpcMsg) {
				defer wg.Done()
				res, e := m.dispatch(msg.Method, msg.Params)
				send(msg.ID, res, e)
			}(msg)
			continue
		}
		res, e := m.dispatch(msg.Method, msg.Params)
		if !note {
			send(msg.ID, res, e)
		}
	}
	wg.Wait()
	return sc.Err()
}

func (m *mcpServer) dispatch(method string, params json.RawMessage) (any, *rpcErr) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(params, &p)
		v := mcpVersions[0]
		for _, s := range mcpVersions {
			if s == p.ProtocolVersion {
				v = s
			}
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "tshare", "title": "tshare", "version": version},
			"instructions":    mcpInstructions,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": m.tools()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcErr{-32602, "invalid params: " + err.Error()}
		}
		if len(p.Arguments) == 0 {
			p.Arguments = json.RawMessage("{}")
		}
		text, err := m.call(p.Name, p.Arguments)
		if err != nil {
			return map[string]any{"content": []any{map[string]any{"type": "text", "text": err.Error()}}, "isError": true}, nil
		}
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}, nil
	}
	if strings.HasPrefix(method, "notifications/") {
		return nil, nil
	}
	return nil, &rpcErr{-32601, "method not found: " + method}
}

const mcpInstructions = "tshare publishes files, folders and websites from this machine as secret HTTPS links " +
	"over Tailscale Funnel. Links are PUBLIC unless tailnet_only or local is set — share only what the user " +
	"asked to share, and prefer a password and a short expiry for anything private. Shares keep running after " +
	"this session; stop them with share_stop. Call tshare_options to see every flag for extra_args."

// ---------------------------------------------------------------------------
// tools

func (m *mcpServer) tools() []map[string]any {
	str := func(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
	boolean := func(desc string) map[string]any { return map[string]any{"type": "boolean", "description": desc} }
	obj := func(props map[string]any, required ...string) map[string]any {
		s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
		if len(required) > 0 {
			s["required"] = required
		}
		return s
	}
	ro := map[string]any{"readOnlyHint": true, "openWorldHint": false}
	tools := []map[string]any{
		{"name": "share_list", "title": "List shares",
			"description": "List the shares running on this machine: id, title, link, mode, expiry, password, downloads.",
			"inputSchema": obj(map[string]any{}), "annotations": ro},
		{"name": "share_info", "title": "Share details",
			"description": "Live details of one running share (uptime, viewers, bytes served…).",
			"inputSchema": obj(map[string]any{"id": str("The share's id, from share_list.")}, "id"), "annotations": ro},
		{"name": "tshare_options", "title": "tshare options",
			"description": "Every tshare option with its explanation, for building extra_args. Optional filter text.",
			"inputSchema": obj(map[string]any{"filter": str("Only options whose name or explanation contains this.")}), "annotations": ro},
		{"name": "tshare_doctor", "title": "Check setup",
			"description": "Check Tailscale, Funnel and the optional tools tshare uses; explains what to fix.",
			"inputSchema": obj(map[string]any{}), "annotations": ro},
	}
	if m.readOnly {
		return tools
	}
	expires := "How long the link lives: 30m, 2h, 1d, 1w or never. Default " + m.defExpires + "."
	scope := "Public on the internet by default."
	if m.tailnetOnly {
		scope = "This server keeps every share tailnet-only (not public)."
	}
	return append(tools,
		map[string]any{"name": "share_create", "title": "Share something",
			"description": "Share a file or folder, publish a website, or open an upload inbox. Returns the link. " + scope +
				" Shares run in the background until they expire or are stopped.",
			"inputSchema": obj(map[string]any{
				"path":         str("File, folder or URL to share. For upload_inbox, the folder files arrive in."),
				"website":      boolean("Serve a folder (or a lone .html) as a live website instead of a file listing."),
				"root":         boolean("Publish at https://<host>/ instead of a secret path, so /absolute links work. Not secret."),
				"password":     str("Require this password to open the link."),
				"expires":      str(expires),
				"persist":      boolean("Keep the share across reboots, on the same link."),
				"tailnet_only": boolean("Only the user's Tailscale network can open it — not public."),
				"local":        boolean("Local network only, no Tailscale."),
				"upload_inbox": boolean("A link that others upload files TO, into path."),
				"allow_upload": boolean("A shared folder that also accepts uploads."),
				"once":         boolean("The link stops working after one download."),
				"name":         str("A readable path instead of a random secret one (less secret)."),
				"extra_args": map[string]any{"type": "array", "items": map[string]any{"type": "string"},
					"description": "Any other tshare flags, e.g. [\"--max-rate\", \"2M\"]. See tshare_options."},
			}),
			"annotations": map[string]any{"destructiveHint": false, "openWorldHint": true}},
		map[string]any{"name": "share_update", "title": "Change a share",
			"description": "Change a running share without restarting it: password, expiry, download limit.",
			"inputSchema": obj(map[string]any{
				"id":            str("The share's id, from share_list."),
				"password":      str("New password; empty string removes it."),
				"expires":       str("New expiry from now: 30m, 2h, 1d, 1w or never."),
				"max_downloads": map[string]any{"type": "integer", "description": "Stop after this many downloads (0 = no limit)."},
			}, "id"),
			"annotations": map[string]any{"destructiveHint": false, "idempotentHint": true}},
		map[string]any{"name": "share_stop", "title": "Stop a share",
			"description": "Stop one share; its link stops working immediately.",
			"inputSchema": obj(map[string]any{"id": str("The share's id, from share_list.")}, "id"),
			"annotations": map[string]any{"destructiveHint": true, "idempotentHint": true}},
	)
}

func (m *mcpServer) call(name string, raw json.RawMessage) (string, error) {
	dec := func(v any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(v); err != nil {
			return fmt.Errorf("invalid arguments: %v", err)
		}
		return nil
	}
	write := map[string]bool{"share_create": true, "share_update": true, "share_stop": true}
	if m.readOnly && write[name] {
		return "", errors.New("this tshare MCP server is read-only")
	}
	switch name {
	case "share_list":
		var shares []map[string]any
		for _, r := range liveShares() {
			shares = append(shares, mcpShareView(r))
		}
		if len(shares) == 0 {
			return "No shares are running.", nil
		}
		return pretty(shares), nil
	case "share_info":
		var a struct{ ID string }
		if err := dec(&a); err != nil {
			return "", err
		}
		return shareInfo(a.ID)
	case "tshare_options":
		var a struct{ Filter string }
		if err := dec(&a); err != nil {
			return "", err
		}
		return pretty(mcpOptions(a.Filter, m)), nil
	case "tshare_doctor":
		out, err := runSelf(60*time.Second, "doctor")
		if err != nil {
			return "", err
		}
		return out, nil
	case "share_create":
		var a mcpCreate
		if err := dec(&a); err != nil {
			return "", err
		}
		return m.create(a)
	case "share_update":
		var a struct {
			ID           string
			Password     *string
			Expires      *string
			MaxDownloads *int64 `json:"max_downloads"`
		}
		if err := dec(&a); err != nil {
			return "", err
		}
		var args []string
		if a.Password != nil {
			args = append(args, "-p", *a.Password)
		}
		if a.Expires != nil {
			args = append(args, "-e", *a.Expires)
		}
		if a.MaxDownloads != nil {
			args = append(args, "-n", fmt.Sprint(*a.MaxDownloads))
		}
		if len(args) == 0 {
			return "", errors.New("nothing to change: give password, expires or max_downloads")
		}
		return updateShare(a.ID, args)
	case "share_stop":
		var a struct{ ID string }
		if err := dec(&a); err != nil {
			return "", err
		}
		if err := stopShare(a.ID); err != nil {
			return "", err
		}
		return "Stopped " + a.ID + " — its link no longer works.", nil
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

type mcpCreate struct {
	Path        string   `json:"path"`
	Website     bool     `json:"website"`
	Root        bool     `json:"root"`
	Password    string   `json:"password"`
	Expires     string   `json:"expires"`
	Persist     bool     `json:"persist"`
	TailnetOnly bool     `json:"tailnet_only"`
	Local       bool     `json:"local"`
	UploadInbox bool     `json:"upload_inbox"`
	AllowUpload bool     `json:"allow_upload"`
	Once        bool     `json:"once"`
	Name        string   `json:"name"`
	ExtraArgs   []string `json:"extra_args"`
}

// argv turns a create request into a tshare command line, enforcing the
// server's fences. Split from create so it can be tested without launching.
func (m *mcpServer) argv(a mcpCreate) ([]string, error) {
	path := expandHome(strings.TrimSpace(a.Path))
	switch {
	case path == "-":
		return nil, errors.New("stdin can't be shared from here — give a file, folder or URL")
	case path != "" && !looksLikeURL(path):
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, fmt.Errorf("%s doesn't exist", path)
		}
		if !m.allowed(real) {
			return nil, fmt.Errorf("%s is outside the folders this server may share (%s)", path, strings.Join(m.allow, ", "))
		}
		path = abs
	}
	if err := checkCallerArgs(a.ExtraArgs); err != nil {
		return nil, err
	}
	for _, x := range a.ExtraArgs {
		if mcpDeniedFlags[flagName(x)] {
			return nil, fmt.Errorf("%s is refused here: it chooses a program to run on this machine", x)
		}
	}

	b := newBuilder(nil)
	b.setTarget(path)
	b.host = false
	if a.Website {
		switch {
		case b.isDirTarget() && b.stack != "" && b.stack != "static" && !m.allowRun:
			return nil, fmt.Errorf("%s is an app (%s): publishing it means running its code, which this server "+
				"doesn't do unless started with --allow-run", a.Path, b.stack)
		case b.isDirTarget() && b.stack != "":
			b.host = true // tshare host: a static site, or (with --allow-run) the app it finds
		default:
			if err := b.set("site", true); err != nil {
				return nil, err
			}
		}
	}
	expires := a.Expires
	if expires == "" && !hasFlag(a.ExtraArgs, "expires", "e") {
		expires = m.defExpires
	}
	set := []struct {
		name string
		v    any
	}{
		{"root", a.Root}, {"persist", a.Persist}, {"tailnet", a.TailnetOnly || m.tailnetOnly},
		{"local", a.Local}, {"upload", a.UploadInbox}, {"allow-upload", a.AllowUpload}, {"once", a.Once},
		{"password", a.Password}, {"expires", expires}, {"name", a.Name},
	}
	for _, s := range set {
		if err := b.set(s.name, s.v); err != nil {
			return nil, err
		}
	}
	if b.target == "" && !b.needsNoTarget() && !hasFlag(a.ExtraArgs, "hub", "room", "call", "kuma", "dashboard", "blackhole", "i") {
		return nil, errors.New("give a path to share (a file, folder or URL)")
	}
	return append(b.argv(), a.ExtraArgs...), nil
}

func (m *mcpServer) create(a mcpCreate) (string, error) {
	argv, err := m.argv(a)
	if err != nil {
		return "", err
	}
	rec, err := launchShare(argv)
	if err != nil {
		return "", err
	}
	v := mcpShareView(rec)
	summary := fmt.Sprintf("Sharing %s at %s (id %s", v["title"], v["url"], rec.ID)
	if e, ok := v["expires_in"]; ok {
		summary += ", expires in " + e.(string)
	} else {
		summary += ", never expires"
	}
	if rec.Password {
		summary += ", password required"
	}
	return summary + ").\n\n" + pretty(v), nil
}

func (m *mcpServer) allowed(real string) bool {
	if len(m.allow) == 0 {
		return true
	}
	for _, root := range m.allow {
		if real == root || strings.HasPrefix(real, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func hasFlag(args []string, names ...string) bool {
	for _, a := range args {
		for _, n := range names {
			if flagName(a) == n {
				return true
			}
		}
	}
	return false
}

func mcpShareView(r stateRec) map[string]any {
	v := map[string]any{"id": r.ID, "title": dashName(r), "url": r.URL, "mode": r.Mode,
		"password": r.Password, "persisted": isPersisted(r.ID), "downloads": r.Downloads,
		"uploads": r.Uploads, "public": !r.Tailnet && !r.Local}
	if r.GameJoin != "" {
		v["url"], v["host_url"] = r.GameJoin, r.GameHost
	}
	if !r.Expires.IsZero() {
		v["expires_in"] = humanDur(time.Until(r.Expires))
	}
	return v
}

func mcpOptions(filter string, m *mcpServer) []map[string]any {
	f := strings.ToLower(filter)
	var out []map[string]any
	for _, o := range newBuilder(nil).opts {
		if reservedFlags[o.primary] || mcpDeniedFlags[o.primary] {
			continue
		}
		if f != "" && !strings.Contains(strings.ToLower(strings.Join(o.names, " ")+" "+o.desc), f) {
			continue
		}
		e := map[string]any{"flag": o.flag(), "section": strings.ToLower(o.section), "takes_value": !o.isBool,
			"description": o.desc}
		if len(o.names) > 1 {
			var al []string
			for _, n := range o.names {
				if n != o.primary {
					if len(n) == 1 {
						al = append(al, "-"+n)
					} else {
						al = append(al, "--"+n)
					}
				}
			}
			e["aliases"] = al
		}
		if o.hint != "" {
			e["value"] = o.hint
		}
		if o.defOn {
			e["default"] = "on"
		} else if !o.isBool && o.def != "" && o.def != "0" && !o.secret {
			e["default"] = o.def
		}
		out = append(out, e)
	}
	return out
}

func pretty(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
