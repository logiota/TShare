//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// -s: reverse-proxy an already-running local server over the funnel

// isLocalServerURL reports whether a URL points at a local/loopback server,
// in which case it should be proxied ("not a website" to download).
func isLocalServerURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "0.0.0.0" || h == "::1" || strings.HasPrefix(h, "127.")
}

// hostPort returns host:port for a URL, filling in the scheme's default port.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return u.Hostname() + ":443"
	}
	return u.Hostname() + ":80"
}

// ---------------------------------------------------------------------------
// managed servers: THE one engine for every server tshare launches and owns —
// `tshare run`, `tshare host`, --room (MiroTalk), --kuma (Uptime Kuma) and the
// copyparty folder backend. One launch / readiness / crash-detect / stop path,
// one proxy builder, and every proc lands in s.procs so it's recorded in the
// share's state and reaped by cleanup, `tshare rm` and `tshare panic` alike.

const tmuxSession = "tshare"

// srvSpec describes a server to launch.
type srvSpec struct {
	name string        // label: log file, tmux window, messages
	dir  string        // working dir ("" = inherit)
	env  []string      // extra environment (KEY=VAL)
	argv []string      // command + args
	port int           // >0: bind/health-check this port (also passed as $PORT); 0: auto-detect
	wait time.Duration // readiness deadline (0 = 60s)
	tmux bool          // user-facing server: may run in the shared tmux session (--tmux)
	tee  bool          // also echo its output to our stderr (unless --quiet)
}

// serverProc is a launched server tshare owns and must stop on share exit.
type serverProc struct {
	name    string
	port    int
	tmuxWin string        // "tshare:<name>" if launched in tmux; else ""
	cmd     *exec.Cmd     // child process (own process group) if not tmux
	done    chan struct{} // closed when the child exits (nil for tmux)
	err     error         // child's exit status, valid once done is closed
	logPath string
}

func (s *share) haveTmux() bool { return s.cfg.Tmux && haveExec("tmux") }

// launchServer starts sp and returns once it is listening on a TCP port. A
// server that dies during startup fails fast with the tail of its log instead
// of burning the whole readiness deadline.
func (s *share) launchServer(sp srvSpec) (*serverProc, error) {
	if len(sp.argv) == 0 {
		return nil, errors.New("no command to run")
	}
	argv := append([]string{}, sp.argv...)
	if p, err := exec.LookPath(argv[0]); err == nil {
		argv[0] = p
	} else {
		return nil, fmt.Errorf("%s not found on PATH — install it (e.g. brew install %s)", argv[0], brewSuggest(argv[0]))
	}
	if sp.port > 0 && portListening(sp.port) { // conflict: something already owns it
		return nil, fmt.Errorf("port %d is already in use — free it or pick another (--port)", sp.port)
	}
	// logs can carry the secret /<token> path (copyparty logs requests) → 0600
	logDir := filepath.Join(filepath.Dir(stateDir()), "logs")
	os.MkdirAll(logDir, 0o700)
	p := &serverProc{name: sp.name, port: sp.port, logPath: filepath.Join(logDir, "srv-"+sp.name+".log")}
	env := append([]string{}, sp.env...)
	if sp.port > 0 {
		env = append(env, fmt.Sprintf("PORT=%d", sp.port))
	}

	if sp.tmux && s.haveTmux() {
		if err := tmuxLaunch(sp.name, sp.dir, env, argv, p.logPath); err != nil {
			return nil, err
		}
		p.tmuxWin = tmuxSession + ":" + sp.name
	} else {
		lf, err := os.OpenFile(p.logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, err
		}
		var out io.Writer = lf
		if sp.tee && !s.cfg.Quiet {
			out = io.MultiWriter(lf, os.Stderr)
		}
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = sp.dir
		cmd.Env = append(withoutEnv(os.Environ(), daemonEnv), env...)
		cmd.Stdout, cmd.Stderr = out, out
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // spawns children → kill the group
		if err := cmd.Start(); err != nil {
			lf.Close()
			return nil, fmt.Errorf("starting %s: %w", sp.name, err)
		}
		p.cmd, p.done = cmd, make(chan struct{})
		go func() { p.err = cmd.Wait(); lf.Close(); close(p.done) }()
	}

	if err := s.awaitReady(p, sp.wait); err != nil {
		p.stop()
		return nil, err
	}
	return p, nil
}

// awaitReady polls until p listens, backing off 50ms→400ms, and wakes at once
// if the child exits (the done channel is nil for tmux, so that case never fires).
func (s *share) awaitReady(p *serverProc, limit time.Duration) error {
	if limit <= 0 {
		limit = 60 * time.Second
	}
	deadline := time.Now().Add(limit)
	delay := 50 * time.Millisecond
	for {
		if p.exited() {
			return fmt.Errorf("%s exited during startup (%v)%s", p.name, p.err, logTail(p.logPath, 400))
		}
		if p.port > 0 {
			if portListening(p.port) {
				return nil
			}
		} else if port := s.detectPort(p); port > 0 {
			p.port = port
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not open a port within %s — see %s", p.name, limit, p.logPath)
		}
		select {
		case <-p.done:
		case <-time.After(delay):
		}
		if delay < 400*time.Millisecond {
			delay *= 2
		}
	}
}

func (p *serverProc) exited() bool {
	if p.done == nil {
		return false
	}
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *serverProc) pid() int {
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

// stop terminates the server's whole process group (npm→node, compose→
// containers): SIGTERM, then SIGKILL after 8s. The group is signalled even if
// the leader already exited, so children it left behind are still reaped.
func (p *serverProc) stop() {
	if p == nil {
		return
	}
	if p.tmuxWin != "" {
		exec.Command("tmux", "kill-window", "-t", p.tmuxWin).Run()
		return
	}
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	pid := p.cmd.Process.Pid
	syscall.Kill(-pid, syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(8 * time.Second):
		syscall.Kill(-pid, syscall.SIGKILL)
	}
}

// adopt takes ownership of a launched server: it's stopped with the share and,
// once the share's state file exists, recorded at once (not on the throttled
// flush) so `tshare rm`/`panic` can reap it even if tshare itself crashes.
func (s *share) adopt(p *serverProc) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.procs = append(s.procs, p)
	if !s.lastStateWrite.IsZero() {
		s.stateDirty = true
		s.flushStateLocked()
	}
}

// stopAll stops servers concurrently, so shutdown costs the slowest one's
// grace period rather than the sum of them.
func stopAll(procs []*serverProc) {
	var wg sync.WaitGroup
	for _, p := range procs {
		wg.Add(1)
		go func(p *serverProc) { defer wg.Done(); p.stop() }(p)
	}
	wg.Wait()
}

// withoutEnv drops key from an environment list.
func withoutEnv(env []string, key string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, key+"=") {
			out = append(out, kv)
		}
	}
	return out
}

// logTail returns the last n bytes of a log as an indented block ("" if empty).
func logTail(path string, n int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > n {
		f.Seek(-n, io.SeekEnd)
	}
	b, _ := io.ReadAll(f)
	t := strings.TrimSpace(string(b))
	if t == "" {
		return ""
	}
	return "\n  " + strings.ReplaceAll(t, "\n", "\n  ")
}

// detectPort finds a TCP port a process in this server's tree is listening on.
func (s *share) detectPort(p *serverProc) int {
	var pids []int
	if p.cmd != nil && p.cmd.Process != nil {
		pids = pgroupPids(p.cmd.Process.Pid)
	} else if p.tmuxWin != "" {
		if root := tmuxPanePid(p.tmuxWin); root > 0 {
			pids = append([]int{root}, descendantPids(root, 0)...)
		}
	}
	return listeningPortOf(pids)
}

func portListening(port int) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

var lsofListenRe = regexp.MustCompile(`:(\d+) \(LISTEN\)`)

// listeningPortOf returns the first TCP port any of pids is LISTENing on (lsof).
func listeningPortOf(pids []int) int {
	if len(pids) == 0 || !haveExec("lsof") {
		return 0
	}
	out, err := exec.Command("lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-a", "-p", joinInts(pids, ",")).Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		if m := lsofListenRe.FindStringSubmatch(line); m != nil {
			if n, _ := strconv.Atoi(m[1]); n > 0 {
				return n
			}
		}
	}
	return 0
}

func pgroupPids(pgid int) []int {
	out, _ := exec.Command("pgrep", "-g", strconv.Itoa(pgid)).Output()
	return parsePids(out)
}

func descendantPids(pid, depth int) []int {
	if depth > 6 {
		return nil
	}
	out, _ := exec.Command("pgrep", "-P", strconv.Itoa(pid)).Output()
	kids := parsePids(out)
	all := append([]int{}, kids...)
	for _, k := range kids {
		all = append(all, descendantPids(k, depth+1)...)
	}
	return all
}

func tmuxPanePid(win string) int {
	out, err := exec.Command("tmux", "list-panes", "-t", win, "-F", "#{pane_pid}").Output()
	if err != nil {
		return 0
	}
	if p := parsePids(out); len(p) > 0 {
		return p[0]
	}
	return 0
}

func parsePids(b []byte) []int {
	var out []int
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func joinInts(xs []int, sep string) string {
	var b strings.Builder
	for i, x := range xs {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(strconv.Itoa(x))
	}
	return b.String()
}

// tmuxLaunch runs argv (with env) as a window of the shared 'tshare' session,
// creating the session if needed. The pane stays after the process exits
// (remain-on-exit) so a crash is inspectable, and output is teed to logPath.
func tmuxLaunch(name, dir string, env, argv []string, logPath string) error {
	shellCmd := tmuxShellCmd(env, argv)
	var cmd *exec.Cmd
	if exec.Command("tmux", "has-session", "-t", tmuxSession).Run() == nil {
		cmd = exec.Command("tmux", "new-window", "-t", tmuxSession, "-n", name, "-c", dir, shellCmd)
	} else {
		cmd = exec.Command("tmux", "new-session", "-d", "-s", tmuxSession, "-n", name, "-c", dir, shellCmd)
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tmux: %s", strings.TrimSpace(string(out)))
	}
	win := tmuxSession + ":" + name
	exec.Command("tmux", "set-option", "-t", win, "remain-on-exit", "on").Run()
	exec.Command("tmux", "pipe-pane", "-t", win, "-o", "cat >> "+shQuote(logPath)).Run()
	return nil
}

func tmuxShellCmd(env, argv []string) string {
	parts := []string{"exec", "env"}
	for _, e := range env {
		parts = append(parts, shQuote(e))
	}
	for _, a := range argv {
		parts = append(parts, shQuote(a))
	}
	return strings.Join(parts, " ")
}

func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// brewSuggest maps a missing command to its usual Homebrew formula (best-effort;
// tshare bundles nothing — it just suggests the install).
func brewSuggest(cmd string) string {
	switch filepath.Base(cmd) {
	case "node", "npm", "npx":
		return "node"
	case "python", "python3", "pip", "pip3":
		return "python"
	case "php":
		return "php"
	case "ruby", "gem", "bundle":
		return "ruby"
	case "docker":
		return "docker (Docker Desktop)"
	case "caddy":
		return "caddy"
	default:
		return filepath.Base(cmd)
	}
}

// newProxy builds the reverse proxy tshare puts in front of any upstream — -s,
// `run`/`host`, and the copyparty backend. keepHost=false presents the
// upstream's own Host (dev-server host checks pass); keepHost=true forwards
// the visitor's Host. WebSockets/HMR upgrade through as usual.
func newProxy(u *url.URL, c *config, what string, keepHost bool) *httputil.ReverseProxy {
	base := strings.TrimSuffix(u.Path, "/")
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			if !keepHost {
				req.Host = u.Host
			}
			if base != "" {
				req.URL.Path = base + req.URL.Path
				if req.URL.RawPath != "" {
					req.URL.RawPath = base + req.URL.RawPath
				}
			}
			if _, ok := req.Header["User-Agent"]; !ok {
				req.Header.Set("User-Agent", "") // don't inject Go's default UA
			}
		},
		FlushInterval: 250 * time.Millisecond, // stream downloads
		BufferPool:    proxyBufPool,           // reuse 64 KiB buffers (less GC)
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
			if errors.Is(e, context.Canceled) {
				return // visitor went away mid-transfer: nothing to report or send
			}
			if !c.Quiet {
				log.Printf("  %s proxy error: %v", what, e)
			}
			http.Error(w, "502 "+what+" not reachable", http.StatusBadGateway)
		},
	}
}

// bufPool is an httputil.BufferPool backed by a sync.Pool of 64 KiB slices, so
// the reverse proxy reuses transfer buffers instead of allocating per request.
type bufPool struct{ p sync.Pool }

func (b *bufPool) Get() []byte  { return b.p.Get().([]byte) }
func (b *bufPool) Put(x []byte) { b.p.Put(x) }

var proxyBufPool = &bufPool{p: sync.Pool{New: func() any { return make([]byte, 64<<10) }}}

func setupServer(c *config, s *share) error {
	u, err := url.Parse(c.Paths[0])
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("-s needs an http(s) URL, e.g. tshare -s http://localhost:8000")
	}
	s.mode = "server"
	s.srvURL = c.Paths[0]
	s.roots = []rootEnt{{Name: u.Host, Abs: c.Paths[0]}} // placeholder for shared code
	s.srvProxy = newProxy(u, c, "upstream", false)
	// best-effort: warn (don't fail) if nothing is listening yet
	d := net.Dialer{Timeout: 800 * time.Millisecond}
	if conn, derr := d.Dial("tcp", hostPort(u)); derr == nil {
		conn.Close()
	} else if !c.Quiet {
		log.Printf("  ⚠ nothing answering at %s yet — the proxy will work once your server is up", s.srvURL)
	}
	if !c.Quiet {
		log.Printf("  ▷ reverse-proxying %s", s.srvURL)
	}
	return nil
}

// setupRun launches a command that serves on a port (auto-detected unless
// --port), then reverse-proxies it over the funnel — the generic `tshare run`
// / `host` engine. Reuses the managed-server launcher and the -s proxy.
func setupRun(c *config, s *share) error {
	dir := c.RunDir
	if dir == "" {
		dir, _ = os.Getwd()
	}
	// --name is an explicit label and must win over the auto-derived name
	// (host-<dirname> from `tshare host`, or run-<id>).
	name := c.Name
	if name == "" {
		name = c.RunName
	}
	if name == "" {
		name = "run-" + s.id
	}
	// In run mode --port is the UPSTREAM (node) port; tshare's own backend
	// listener must NOT reuse it, so free c.Port for auto-pick after capturing.
	wantPort := c.Port
	c.Port = 0
	// -b: the detached child re-runs this and owns the server. Launching here
	// too would double-start it (a port clash with --port) and orphan ours.
	if c.Background && !c.daemonChild {
		s.mode = "server"
		s.roots = []rootEnt{{Name: name, Abs: strings.Join(c.RunCmd, " ")}}
		return nil
	}
	if !c.Quiet {
		how := "as a child process"
		if s.haveTmux() {
			how = "in tmux (attach: tmux attach -t " + tmuxSession + ")"
		}
		log.Printf("  ▶ launching %s %s …", strings.Join(c.RunCmd, " "), how)
	}
	p, err := s.launchServer(srvSpec{name: name, dir: dir, argv: c.RunCmd, port: wantPort, tmux: true})
	if err != nil {
		return err
	}
	s.adopt(p)
	s.mode = "server"
	s.srvURL = fmt.Sprintf("http://127.0.0.1:%d", p.port)
	u, _ := url.Parse(s.srvURL)
	s.srvProxy = newProxy(u, c, "upstream", false)
	s.roots = []rootEnt{{Name: name, Abs: s.srvURL}}
	if !c.Quiet {
		log.Printf("  ▷ %s listening on :%d — proxied over the funnel", name, p.port)
	}
	return nil
}

// funnelUnavailable spots the tailscale errors that mean "Funnel isn't enabled
// for this node", so we can transparently fall back to tailnet-only serve (#68).
func funnelUnavailable(out string) bool {
	o := strings.ToLower(out)
	for _, sig := range []string{"funnel", "not enabled", "attribute", "not allowed", "https"} {
		if strings.Contains(o, sig) {
			return true
		}
	}
	return false
}

// splitRunArgs separates share flags from the command to run. Everything after
// a literal "--" is the command; otherwise the first non-flag token and the
// rest are the command (so `tshare run --port 3000 node app.js` works too).
// Share flags may also be placed AFTER the command: a trailing run of tshare
// flags is lifted back onto the share, so `tshare run -- node app.js --tmux
// --name demo` behaves the same as the flags-before form.
func splitRunArgs(args []string) (flags, cmd []string) {
	for i, a := range args {
		if a == "--" {
			flags, cmd = args[:i], args[i+1:]
			break
		}
	}
	if cmd == nil {
		// no "--": walk flags, stop at the first bare token that isn't a flag value
		i := 0
		for i < len(args) {
			a := args[i]
			if !strings.HasPrefix(a, "-") {
				flags, cmd = args[:i], args[i:]
				break
			}
			i++
			// a known value-taking flag consumes the next token
			if runValueFlag(a) && i < len(args) && !strings.HasPrefix(args[i], "-") {
				i++
			}
		}
		if cmd == nil {
			flags, cmd = args, nil
		}
	}
	if tail := trailingShareFlags(cmd); len(tail) > 0 {
		flags = append(append([]string(nil), flags...), tail...)
		cmd = cmd[:len(cmd)-len(tail)]
	}
	return flags, cmd
}

// trailingShareFlags detects a trailing run of tshare flags on a run command
// (e.g. "-- node app.js --tmux --name demo") and returns them. Nothing is
// lifted unless the run includes a flag that is unmistakably tshare's (tmux,
// -b, --persist, …), so an app's own trailing options are left alone.
func trailingShareFlags(cmd []string) []string {
	if len(cmd) < 2 {
		return nil
	}
	i := len(cmd)
	for i > 0 {
		if !isTshareFlag(cmd[i-1]) {
			if i >= 2 && isTshareFlag(cmd[i-2]) {
				i -= 2 // a tshare value flag + its value
				continue
			}
			break
		}
		i--
	}
	cluster := cmd[i:]
	if len(cluster) == 0 || !tshareIntent(cluster) {
		return nil
	}
	return cluster
}

// isTshareFlag reports whether tok names one of tshare's own flags (value-taking
// or boolean), so trailing-flag lifting only ever peels tshare flags off a
// command and never touches an app's options.
func isTshareFlag(tok string) bool {
	name := strings.TrimLeft(tok, "-")
	if name == "" || name == tok {
		return false
	}
	switch name {
	case "port", "p", "password", "e", "expires", "name", "n", "max", "https-port",
		"max-rate", "max-bytes", "min-free", "dir", "abuse-contact", "profile", "template",
		"token-len", "max-upload", "tailscale-bin", "filename", "yt-format", "yt-args",
		"room-name", "mirotalk-url", "mirotalk-dir", "mirotalk-port",
		"mirotalk-jwt-key", "kuma-port", "kuma-dir", "copyparty-bin", "copyparty-args",
		"rar-size", "stun", "turn", "turn-user", "turn-pass", "cq":
		return true
	}
	return tshareBoolFlag(name)
}

func tshareBoolFlag(name string) bool {
	switch name {
	case "once", "t", "tailnet", "u", "upload", "allow-upload", "z", "zip", "site",
		"web", "gamelink", "g", "l", "local", "lan", "no-lan", "inline", "b", "bg",
		"q", "qr", "c", "copy", "no-qr", "no-copy", "no-notify", "no-open", "open",
		"quiet", "json", "Y", "yt-dlp", "yt-audio", "a", "playlist", "fetch",
		"progressive", "live", "s", "server", "require-identity", "i", "blackhole",
		"room", "mirotalk", "p2p", "p2pi", "call", "hub", "tmux", "kuma", "dashboard",
		"web-ui", "rar", "full", "ro", "read-only", "lan-https", "no-config", "watch",
		"persist", "no-repl", "265", "hevc", "transcode", "strip-exif", "no-gallery",
		"encrypt", "copyparty", "no-copyparty":
		return true
	}
	return false
}

// runIntentFlags are tshare options unlikely to belong to a launched app, so a
// run containing any of them is treated as passing tshare flags after the --.
func tshareIntent(cluster []string) bool {
	for _, c := range cluster {
		if tshareIntentSet[strings.TrimLeft(c, "-")] {
			return true
		}
	}
	return false
}

var tshareIntentSet = map[string]bool{
	"b": true, "bg": true, "tmux": true, "persist": true, "no-repl": true,
	"room": true, "mirotalk": true, "kuma": true, "hub": true, "dashboard": true,
	"web-ui": true, "call": true, "p2p": true, "p2pi": true, "blackhole": true,
	"i": true, "rar": true, "gamelink": true, "g": true, "quiet": true, "json": true,
	"no-config": true, "tailnet": true, "t": true, "upload": true, "u": true,
	"full": true, "ro": true, "read-only": true, "no-open": true, "no-notify": true,
	"no-qr": true, "no-copy": true, "require-identity": true, "site": true,
	"web": true, "local": true, "l": true, "watch": true, "encrypt": true,
}

func runValueFlag(f string) bool {
	switch strings.TrimLeft(f, "-") {
	case "port", "p", "password", "e", "expires", "name", "n", "max", "https-port",
		"max-rate", "max-bytes", "min-free", "dir", "abuse-contact", "profile", "template",
		"filename", "__id", "__tmp", "__tmpdir", "__enckey", "__gamesid": // + daemon/resume internals
		return true
	}
	return false
}

func init() {
	register(cmdRun, "run")
	register(cmdHost, "host")
	register(cmdTmux, "tmux")
}

// cmdRun: launch any command that serves on a port and expose it over the funnel.
//
//	tshare run --port 3000 -- npm start
//	tshare run -- python3 -m http.server 8000
func cmdRun(args []string) {
	flags, cmd := splitRunArgs(args)
	c := defaultConfig()
	applyConfig(c, flags)
	if err := parseArgs(flags, c); err != nil {
		os.Exit(2)
	}
	if len(cmd) == 0 && len(c.Paths) > 0 { // command landed in positionals
		cmd, c.Paths = c.Paths, nil
	}
	if len(cmd) == 0 {
		log.Fatal("usage: tshare run [flags] -- <command…>\n" +
			"  e.g. tshare run --port 3000 -- npm start\n" +
			"       tshare run -- python3 -m http.server 8000   (port auto-detected)")
	}
	c.RunCmd = cmd
	if err := runShare(c); err != nil {
		log.Fatalf("tshare: %v", err)
	}
}

// detectStack maps a project folder to a start command, best-effort, for the
// one-stop `tshare host <dir>`. Bundles nothing — if the runtime is missing,
// launchServer reports a brew-install suggestion.
func detectStack(dir string) (cmd []string, kind string) {
	has := func(f string) bool { return fileExists(filepath.Join(dir, f)) }
	switch {
	case has("package.json"):
		// honor an explicit "start" script; else fall back to a common entry
		if b, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil &&
			regexp.MustCompile(`"scripts"\s*:\s*{[^}]*"start"\s*:`).Match(b) {
			return []string{"npm", "start"}, "node (npm start)"
		}
		for _, e := range []string{"server.js", "index.js", "app.js", "main.js"} {
			if has(e) {
				return []string{"node", e}, "node (" + e + ")"
			}
		}
		return []string{"npm", "start"}, "node (npm start)"
	case has("compose.yaml") || has("compose.yml") || has("docker-compose.yml") || has("docker-compose.yaml"):
		return []string{"docker", "compose", "up"}, "docker compose"
	case has("app.py"), has("wsgi.py"), has("manage.py"):
		if has("manage.py") {
			return []string{"python3", "manage.py", "runserver", "0.0.0.0:8000"}, "django"
		}
		return []string{"python3", filepath.Base(firstExisting(dir, "app.py", "wsgi.py"))}, "python"
	case has("requirements.txt") && has("main.py"):
		return []string{"python3", "main.py"}, "python"
	case has("index.php"):
		return []string{"php", "-S", "0.0.0.0:8080", "-t", "."}, "php"
	case has("Gemfile") && has("config.ru"):
		return []string{"bundle", "exec", "rackup", "-o", "0.0.0.0"}, "ruby (rack)"
	case has("index.html"):
		return nil, "static" // handled by --site, not a launched server
	}
	return nil, ""
}

func firstExisting(dir string, names ...string) string {
	for _, n := range names {
		if fileExists(filepath.Join(dir, n)) {
			return n
		}
	}
	return names[0]
}

// cmdHost: the one-stop "just host this folder" — auto-detect the stack and run
// it (static folders route to --site; everything else to the run engine).
func cmdHost(args []string) {
	// a non-flag arg that names an existing directory is the target dir
	dir := "."
	var rest []string
	for _, a := range args {
		if fi, err := os.Stat(a); !strings.HasPrefix(a, "-") && err == nil && fi.IsDir() {
			dir = a
		} else {
			rest = append(rest, a)
		}
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	cmd, kind := detectStack(abs)
	if kind == "" {
		log.Fatalf("tshare host: couldn't detect a stack in %s\n"+
			"  (looked for package.json / compose.yml / app.py / index.php / index.html)\n"+
			"  run it explicitly:  tshare run --dir %s -- <start command>", abs, abs)
	}
	fmt.Fprintf(os.Stderr, "  ⓘ detected %s in %s\n", kind, abs)
	c := defaultConfig()
	applyConfig(c, rest)
	if err := parseArgs(rest, c); err != nil {
		os.Exit(2)
	}
	c.Paths = nil
	if kind == "static" { // a plain site — use the existing static engine
		c.Site = true
		c.Paths = []string{abs}
	} else {
		c.RunCmd = cmd
		c.RunDir = abs
		c.RunName = "host-" + sanitizeRoomName(filepath.Base(abs))
	}
	if err := runShare(c); err != nil {
		log.Fatalf("tshare: %v", err)
	}
}

// cmdTmux lists the managed servers running in the shared 'tshare' tmux session
// (the "backgrounded sessions in one square") and how to attach.
func cmdTmux(args []string) {
	if !haveExec("tmux") {
		fmt.Println("tmux not installed (brew install tmux). Servers run as child processes without --tmux.")
		return
	}
	out, err := exec.Command("tmux", "list-windows", "-t", tmuxSession,
		"-F", "#{window_index}: #{window_name}  [#{pane_current_command}]  #{?window_active,(active),}").CombinedOutput()
	if err != nil {
		fmt.Println("no tshare tmux session — start a server with --tmux (e.g. tshare --tmux --room, or tshare run --tmux -- npm start)")
		return
	}
	fmt.Printf("  tmux session %q — attach with:  tmux attach -t %s\n\n", tmuxSession, tmuxSession)
	fmt.Print(string(out))
}
