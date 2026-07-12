//go:build unix

package main

import (
	"errors"
	"fmt"
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
// managed servers: launch a local server (in tmux or as a child), wait for its
// port, and reverse-proxy it over the funnel. Shared by `tshare run`, `tshare
// host <dir>`, and --room (MiroTalk) so there's one launch/health/stop path.

const tmuxSession = "tshare"

// serverProc is a launched server tshare owns and must stop on share exit.
type serverProc struct {
	name    string
	port    int
	tmuxWin string    // "tshare:<name>" if launched in tmux; else ""
	cmd     *exec.Cmd // child process (process group) if not tmux
	logPath string
}

func (s *share) haveTmux() bool { return s.cfg.Tmux && haveExec("tmux") }

// launchServer starts argv (in dir, with extra env) and returns once it is
// listening on a TCP port. wantPort>0 uses that port (passed as $PORT and
// health-checked); wantPort==0 auto-detects whatever port the process opens.
func (s *share) launchServer(name, dir string, extraEnv, argv []string, wantPort int) (*serverProc, error) {
	if len(argv) == 0 {
		return nil, errors.New("no command to run")
	}
	if p, err := exec.LookPath(argv[0]); err == nil {
		argv[0] = p
	} else {
		return nil, fmt.Errorf("%s not found on PATH — install it (e.g. brew install %s)", argv[0], brewSuggest(argv[0]))
	}
	if wantPort > 0 && portListening(wantPort) { // conflict: something already owns it
		return nil, fmt.Errorf("port %d is already in use — free it or pick another (--port)", wantPort)
	}
	logDir := filepath.Join(filepath.Dir(stateDir()), "logs")
	os.MkdirAll(logDir, 0o755)
	p := &serverProc{name: name, port: wantPort, logPath: filepath.Join(logDir, "srv-"+name+".log")}
	env := append([]string{}, extraEnv...)
	if wantPort > 0 {
		env = append(env, fmt.Sprintf("PORT=%d", wantPort))
	}

	if s.haveTmux() {
		if err := tmuxLaunch(name, dir, env, argv, p.logPath); err != nil {
			return nil, err
		}
		p.tmuxWin = tmuxSession + ":" + name
	} else {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), env...)
		if f, err := os.Create(p.logPath); err == nil {
			cmd.Stdout, cmd.Stderr = f, f
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // spawns children → kill the group
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("starting %s: %w", name, err)
		}
		p.cmd = cmd
	}

	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if wantPort > 0 {
			if portListening(wantPort) {
				return p, nil
			}
		} else if port := s.detectPort(p); port > 0 {
			p.port = port
			return p, nil
		}
		time.Sleep(400 * time.Millisecond)
	}
	p.stop()
	return nil, fmt.Errorf("%s did not open a port within 60s — see %s", name, p.logPath)
}

func (p *serverProc) pid() int {
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

func (p *serverProc) stop() {
	if p == nil {
		return
	}
	if p.tmuxWin != "" {
		exec.Command("tmux", "kill-window", "-t", p.tmuxWin).Run()
		return
	}
	if p.cmd != nil && p.cmd.Process != nil {
		pid := p.cmd.Process.Pid
		syscall.Kill(-pid, syscall.SIGTERM) // whole group (npm→node, compose→containers)
		done := make(chan struct{})
		go func() { p.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			syscall.Kill(-pid, syscall.SIGKILL)
		}
	}
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

// newHostProxy builds the reverse proxy tshare puts in front of an upstream
// server (shared by -s and `tshare run`/`host`). Presents the upstream's own
// Host so dev-server host checks pass; WebSockets/HMR upgrade through as usual.
func newHostProxy(u *url.URL, c *config) *httputil.ReverseProxy {
	base := strings.TrimSuffix(u.Path, "/")
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			req.Host = u.Host
			if base != "" {
				req.URL.Path = base + req.URL.Path
			}
		},
		FlushInterval: 250 * time.Millisecond,
		BufferPool:    proxyBufPool,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
			if !c.Quiet {
				log.Printf("  upstream error: %v", e)
			}
			http.Error(w, "502 upstream not reachable", http.StatusBadGateway)
		},
	}
}

func setupServer(c *config, s *share) error {
	u, err := url.Parse(c.Paths[0])
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("-s needs an http(s) URL, e.g. tshare -s http://localhost:8000")
	}
	s.mode = "server"
	s.srvURL = c.Paths[0]
	s.roots = []rootEnt{{Name: u.Host, Abs: c.Paths[0]}} // placeholder for shared code
	s.srvProxy = newHostProxy(u, c)
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
	name := c.RunName
	if name == "" {
		name = "run-" + s.id
	}
	// In run mode --port is the UPSTREAM (node) port; tshare's own backend
	// listener must NOT reuse it, so free c.Port for auto-pick after capturing.
	wantPort := c.Port
	c.Port = 0
	if !c.Quiet {
		how := "as a child process"
		if s.haveTmux() {
			how = "in tmux (attach: tmux attach -t " + tmuxSession + ")"
		}
		log.Printf("  ▶ launching %s %s …", strings.Join(c.RunCmd, " "), how)
	}
	p, err := s.launchServer(name, dir, nil, c.RunCmd, wantPort)
	if err != nil {
		return err
	}
	s.procs = append(s.procs, p)
	s.mode = "server"
	s.srvURL = fmt.Sprintf("http://127.0.0.1:%d", p.port)
	u, _ := url.Parse(s.srvURL)
	s.srvProxy = newHostProxy(u, c)
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
