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

// handleSetup handles the `tshare <app> install|status` subcommands shared by
// every managed node app. Returns false when args ask for something else.
func (a *nodeApp) handleSetup(args []string, c *config) bool {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "install", "setup":
		parseArgs(args[1:], c) // honor --<app>-dir / --<app>-port
		if err := a.install(c); err != nil {
			log.Fatalf("tshare: %v", err)
		}
	case "status":
		parseArgs(args[1:], c)
		a.status(c)
	default:
		return false
	}
	return true
}

func cmdKuma(args []string) {
	c := defaultConfig()
	applyConfig(c, args)
	if kumaApp.handleSetup(args, c) {
		return
	}
	if err := parseArgs(args, c); err != nil {
		os.Exit(2)
	}
	c.Kuma, c.Paths = true, nil
	if err := runShare(c); err != nil {
		log.Fatalf("tshare: %v", err)
	}
}

// cmdRoom implements `tshare room install|status` — the one-time local setup.
func cmdRoom(args []string) {
	c := defaultConfig()
	applyConfig(c, args)
	if !mirotalkApp.handleSetup(args, c) {
		fmt.Println("usage: tshare room install | status   (start a room with: tshare --room)")
	}
}

// ---------------------------------------------------------------------------
// local MiroTalk engine (--room without --mirotalk-url)
//
// One-time setup: `tshare room install` clones github.com/miroslavpejic85/mirotalk
// into ~/.tshare/mirotalk, copies its .env / config templates and installs deps
// (npm). After that `tshare --room <name>` starts it on demand, health-checks
// it, exposes it at the funnel/serve ROOT path (MiroTalk
// is a root-path SPA — it breaks under /<token>/), and stops it again on exit.
// Signaling stays on your node; the actual call media is WebRTC peer-to-peer.
