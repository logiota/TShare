//go:build unix

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Uptime Kuma (--kuma): reuse/start a persistent Uptime Kuma monitor and expose
// it at the funnel ROOT (Uptime Kuma is a root-path SPA — it can't be proxied
// under /<token>/). Docker is the primary, official deploy; a manually-run
// git+npm instance is reused if already listening. tshare NEVER stops Kuma —
// it's a standing service (restart=always) — it only mounts/unmounts the root.

// ---------------------------------------------------------------------------
// native Node apps: --room (MiroTalk) and --kuma (Uptime Kuma). Both are
// installed from GitHub (git clone + npm) and run NATIVELY through the shared
// managed-server engine, so they start on demand and shut down with the share.
// Each is exposed at the funnel ROOT (they're root-path SPAs). No Docker.

type nodeApp struct {
	key, name, repo, health string
	port                    int
	run, env                []string
	templates               [][2]string // src→dst copied post-clone (never clobbered)
	setup                   [][]string  // post-clone install steps, run in the checkout
	flag, sub               string      // how you invoke it (start flag, install subcommand)
}

var mirotalkApp = &nodeApp{
	key: "mirotalk", name: "MiroTalk", repo: "https://github.com/miroslavpejic85/mirotalk",
	health: "mirotalk", port: 7701, run: []string{"npm", "start"}, env: []string{"NODE_ENV=production"},
	templates: [][2]string{{".env.template", ".env"}, {"app/src/config.template.js", "app/src/config.js"}},
	setup:     [][]string{{"npm", "ci", "--omit=dev"}},
	flag:      "--room", sub: "room",
}

var kumaApp = &nodeApp{
	key: "kuma", name: "Uptime Kuma", repo: "https://github.com/louislam/uptime-kuma",
	health: "uptime kuma", port: 7702, run: []string{"node", "server/server.js"}, env: []string{"NODE_ENV=production"},
	// upstream's `npm run setup` = `git checkout <tag> && npm ci … && npm run download-dist`;
	// the git checkout needs a tag our shallow clone doesn't have (and just re-pins the version
	// we already cloned), so run the two real steps directly.
	setup: [][]string{{"npm", "ci", "--omit=dev", "--no-audit"}, {"npm", "run", "download-dist"}},
	flag:  "kuma", sub: "kuma",
}

func (a *nodeApp) dir(c *config) string {
	if a.key == "mirotalk" && c != nil && c.MirotalkDir != "" {
		return c.MirotalkDir
	}
	if a.key == "kuma" && c != nil && c.KumaDir != "" {
		return c.KumaDir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".tshare", a.key)
}

func (a *nodeApp) portOf(c *config) int {
	if a.key == "mirotalk" && c.MirotalkPort > 0 {
		return c.MirotalkPort
	}
	if a.key == "kuma" && c.KumaPort > 0 {
		return c.KumaPort
	}
	return a.port
}

func (a *nodeApp) installed(c *config) bool {
	return fileExists(filepath.Join(a.dir(c), "package.json"))
}

// alive classifies :port — "app" (it), "other" (busy with something else), "" (free).
func (a *nodeApp) alive(port int) string {
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if strings.Contains(strings.ToLower(string(body)), a.health) {
		return "app"
	}
	return "other"
}

// preflight fails fast (before any funnel mount) if the app can't be brought up.
func (a *nodeApp) preflight(c *config) error {
	switch a.alive(a.portOf(c)) {
	case "app":
		return nil
	case "other":
		return fmt.Errorf("port %d is serving something that isn't %s — free it or change its port", a.portOf(c), a.name)
	}
	if a.installed(c) {
		return nil
	}
	return fmt.Errorf("%s isn't installed. one-time setup:  tshare %s install", a.name, a.sub)
}

// start reuses a running instance or launches the checkout natively (managed by
// the server engine → stopped with the share). Adds the proc to s.procs.
func (a *nodeApp) start(s *share) error {
	c := s.cfg
	port := a.portOf(c)
	switch a.alive(port) {
	case "app":
		if !c.Quiet {
			log.Printf("  ▷ reusing %s already running on :%d", a.name, port)
		}
		return nil
	case "other":
		return fmt.Errorf("port %d is busy with a non-%s service", port, a.name)
	}
	if !a.installed(c) {
		return fmt.Errorf("%s isn't installed — run: tshare %s install", a.name, a.sub)
	}
	env := append([]string{}, a.env...)
	if a.key == "kuma" {
		env = append(env, fmt.Sprintf("UPTIME_KUMA_PORT=%d", port)) // Kuma's own port var
	}
	p, err := s.launchServer(a.key+"-"+s.id, a.dir(c), env, append([]string{}, a.run...), port)
	if err != nil {
		return err
	}
	s.procs = append(s.procs, p)
	if !c.Quiet {
		where := "log " + p.logPath
		if p.tmuxWin != "" {
			where = "tmux attach -t " + tmuxSession
		}
		log.Printf("  ▷ %s up on :%d (native, %s)", a.name, port, where)
	}
	return nil
}

// install clones the app from GitHub and runs its native setup (git + node/npm).
func (a *nodeApp) install(c *config) error {
	if !haveExec("git") {
		return errors.New("git is required (brew install git)")
	}
	if !haveExec("node") || !haveExec("npm") {
		return errors.New("node + npm are required for the native app — brew install node, then re-run")
	}
	dir := a.dir(c)
	if fileExists(filepath.Join(dir, "package.json")) {
		fmt.Printf("  ✓ already installed: %s (updating)\n", dir)
		if out, err := exec.Command("git", "-C", dir, "pull", "--ff-only").CombinedOutput(); err != nil {
			fmt.Printf("  ⚠ update skipped: %s\n", strings.TrimSpace(string(out)))
		}
	} else {
		fmt.Printf("  ⇣ cloning %s → %s\n", a.repo, dir)
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return err
		}
		cmd := exec.Command("git", "clone", "--depth", "1", a.repo, dir)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("git clone failed: %w", err)
		}
	}
	for _, cp := range a.templates {
		src, dst := filepath.Join(dir, cp[0]), filepath.Join(dir, cp[1])
		if fileExists(dst) || !fileExists(src) {
			continue
		}
		if b, err := os.ReadFile(src); err == nil && os.WriteFile(dst, b, 0o644) == nil {
			fmt.Printf("  ✓ %s → %s\n", cp[0], cp[1])
		}
	}
	for _, step := range a.setup {
		fmt.Printf("  ⇣ %s …\n", strings.Join(step, " "))
		cmd := exec.Command(step[0], step[1:]...)
		cmd.Dir = dir
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s failed: %w", strings.Join(step, " "), err)
		}
	}
	// remember where it lives so `tshare` finds it next time.
	if err := appendConfigKeys(map[string]string{a.key + "-dir": dir}); err == nil {
		fmt.Printf("  ✓ recorded %s-dir in %s\n", a.key, configPath())
	}
	fmt.Printf("\n  ✓ %s ready — start it:  tshare %s\n", a.name, a.flag)
	return nil
}

func (a *nodeApp) status(c *config) {
	fmt.Printf("  install dir: %s (installed: %v)\n", a.dir(c), a.installed(c))
	st := a.alive(a.portOf(c))
	if st == "" {
		st = "not running"
	}
	fmt.Printf("  port %d:   %s\n", a.portOf(c), st)
}

func cmdKuma(args []string) {
	c := defaultConfig()
	applyConfig(c, args)
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "install", "setup":
		parseArgs(args[1:], c) // honor --kuma-dir / --kuma-port
		if err := kumaApp.install(c); err != nil {
			log.Fatalf("tshare: %v", err)
		}
	case "status":
		parseArgs(args[1:], c)
		kumaApp.status(c)
	default:
		if err := parseArgs(args, c); err != nil {
			os.Exit(2)
		}
		c.Kuma, c.Paths = true, nil
		if err := runShare(c); err != nil {
			log.Fatalf("tshare: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// local MiroTalk engine (--room without --mirotalk-url)
//
// One-time setup: `tshare room install` clones github.com/miroslavpejic85/mirotalk
// into ~/.tshare/mirotalk, copies its .env / config templates and installs deps
// (npm, or docker compose). After that `tshare --room <name>` starts it on
// demand, health-checks it, exposes it at the funnel/serve ROOT path (MiroTalk
// is a root-path SPA — it breaks under /<token>/), and stops it again on exit.
// Signaling stays on your node; the actual call media is WebRTC peer-to-peer.

func haveExec(name string) bool { _, err := exec.LookPath(name); return err == nil }

// cmdRoom implements `tshare room install|status` — the one-time local setup.
// defaultConfig is the base config (defaults) shared by the top-level share
// path and the run/host subcommands, so there's one source of truth.
func defaultConfig() *config {
	return &config{TokenLen: 16, HTTPSPort: 443, MaxUpload: "5G", MinFree: "32G", CQ: 50,
		RarSize:      "1400M",
		MirotalkPort: 7701, KumaPort: 7702,
		STUN: "stun:stun.l.google.com:19302,stun:stun.cloudflare.com:3478",
		Copy: true, LAN: true, Password: os.Getenv("TSHARE_PASSWORD")}
}

// splitRunArgs separates share flags from the command to run. Everything after
// a literal "--" is the command; otherwise the first non-flag token and the
// rest are the command (so `tshare run --port 3000 node app.js` works too).
func splitRunArgs(args []string) (flags, cmd []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	// no "--": walk flags, stop at the first bare token that isn't a flag value
	i := 0
	for i < len(args) {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			return args[:i], args[i:]
		}
		i++
		// a known value-taking flag consumes the next token
		if runValueFlag(a) && i < len(args) && !strings.HasPrefix(args[i], "-") {
			i++
		}
	}
	return args, nil
}

func runValueFlag(f string) bool {
	switch strings.TrimLeft(f, "-") {
	case "port", "p", "password", "e", "expires", "name", "n", "max", "https-port",
		"max-rate", "max-bytes", "min-free", "dir", "abuse-contact", "profile", "template":
		return true
	}
	return false
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
