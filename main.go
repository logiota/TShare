//go:build unix

// tshare — secure secret-link file sharing over Tailscale Funnel.
//
// Default: `tshare <path>` serves a file/dir behind an unguessable token URL
// on the public internet via `tailscale funnel`. Lots of optional knobs:
// passwords, expiry, download limits, upload inboxes, zip, QR, tailnet-only,
// background mode, multi-share management (ls/rm), and a local/LAN mode.
//
// Single binary, stdlib only. macOS + Linux.
//
// main.go is tshare's core, and it builds and works on its own: the command
// registry, share control (the state model; starting, listing, changing and
// stopping shares), and a small built-in share engine. Every other file is a
// module that registers what it adds from init() — the full share engine
// replaces the built-in one, and the rest add commands and front ends.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// entry and command registry

var (
	commands   = map[string]func(args []string){}
	defaultRun = builtinShare // bare `tshare [flags] <path>`; the full engine replaces it

	// defineFlags declares every tshare flag on fs. The flags module sets it;
	// without one the core knows no flags, and refuses to pass any through.
	defineFlags func(fs *flag.FlagSet)

	// loginAgent is the macOS login agent that brings --persist shares back
	// after a reboot, filled in by the agent module; nil when it isn't built in.
	loginAgent *agentHooks
)

type agentHooks struct {
	Installed  func() bool
	Install    func() error
	Remove     func() error
	ForPersist func(quiet bool) // install it on first --persist, saying what it did
}

// register binds a subcommand handler to one or more first-argument names.
func register(run func(args []string), names ...string) {
	for _, n := range names {
		if _, dup := commands[n]; dup {
			panic("tshare: command registered twice: " + n)
		}
		commands[n] = run
	}
}

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	if len(args) > 0 {
		if run, ok := commands[args[0]]; ok {
			run(args[1:])
			return
		}
	}
	defaultRun(args)
}

// ---------------------------------------------------------------------------
// share control: the state every share publishes, and starting, listing,
// changing and stopping shares from code the way the CLI does.
//
// A front end (`tshare gui`, the MCP server) never hosts a share in its own
// process: it runs this same binary as a detached `tshare -b` share and reads
// back the state that share publishes. So a share outlives whatever started
// it, gets exactly the lifecycle of one started by hand (state file, `tshare
// rm`, --persist, the login agent), and a front end crashing takes nothing down.

type stateRec struct {
	ID        string    `json:"id"`
	PID       int       `json:"pid"`
	Token     string    `json:"token"`
	Mode      string    `json:"mode"`
	Title     string    `json:"title,omitempty"` // short human label (filename, host, room name, …)
	URL       string    `json:"url"`
	Target    string    `json:"target"`
	Tailnet   bool      `json:"tailnet_only"`
	Local     bool      `json:"local"`
	HTTPSPort int       `json:"https_port"`
	Port      int       `json:"port"`
	Password  bool      `json:"password"`
	MaxDL     int64     `json:"max_downloads"`
	Downloads int64     `json:"downloads"`
	Uploads   int64     `json:"uploads"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires,omitempty"`
	Procs     []procRec `json:"procs,omitempty"`      // managed servers we own (run/host/room) → reap on rm/panic
	RootMount bool      `json:"root_mount,omitempty"` // we hold the funnel/serve root path
	GameJoin  string    `json:"game_join,omitempty"`  // --gamelink: the JOIN link (child's live session id)
	GameHost  string    `json:"game_host,omitempty"`  // --gamelink: the auto-host (#gnhost) link
}

// procRec is how a managed server is recorded in the share state so another
// process (tshare rm / panic) can reap it: a process-group pid, or a tmux window.
type procRec struct {
	Pid  int    `json:"pid,omitempty"`
	Tmux string `json:"tmux,omitempty"`
}

func stateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	d := filepath.Join(home, ".tshare", "shares")
	os.MkdirAll(d, 0o700)
	return d
}

func stateFile(id string) string { return filepath.Join(stateDir(), id+".json") }

func writeJSON(fp string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := fp + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, fp)
}

// recAlive reports whether a share recorded in state is really still running.
// After a reboot the old state files survive with pids that the kernel has
// since handed to unrelated processes, so a bare pid check reports phantom
// shares (and can make `rm` signal a stranger). A record written before the
// current boot is dead by definition.
func recAlive(r stateRec) bool {
	if !pidAlive(r.PID) {
		return false
	}
	if b := bootTime(); !b.IsZero() && r.Created.Before(b) {
		return false
	}
	return true
}

var (
	bootOnce sync.Once
	bootAt   time.Time
)

// bootTime is when this machine last booted (zero if it can't be determined,
// in which case callers fall back to the plain pid check).
func bootTime() time.Time {
	bootOnce.Do(func() {
		if runtime.GOOS == "darwin" {
			// kern.boottime: "{ sec = 1789000000, usec = 0 } Tue Sep  9 ..."
			out, err := exec.Command("sysctl", "-n", "kern.boottime").Output()
			if err != nil {
				return
			}
			if m := regexp.MustCompile(`sec\s*=\s*(\d+)`).FindSubmatch(out); m != nil {
				if n, err := strconv.ParseInt(string(m[1]), 10, 64); err == nil {
					bootAt = time.Unix(n, 0)
				}
			}
			return
		}
		if b, err := os.ReadFile("/proc/uptime"); err == nil { // linux
			if f := strings.Fields(string(b)); len(f) > 0 {
				if secs, err := strconv.ParseFloat(f[0], 64); err == nil {
					bootAt = time.Now().Add(-time.Duration(secs * float64(time.Second)))
				}
			}
		}
	})
	return bootAt
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// daemonEnv marks a process as a detached -b child. The argv markers below are
// what the child parses; this is the backstop that makes a re-daemonize loop
// impossible even if a future argv layout ever hides those markers.
const daemonEnv = "TSHARE_DAEMON_CHILD"

// insertArgs splices tshare-internal flags in right after the subcommand name
// (or first, for a bare share) — never at the end, where `run … -- cmd` would
// hand them to the user's command instead of to tshare.
func insertArgs(args []string, extra ...string) []string {
	at := 0
	if len(args) > 0 && commands[args[0]] != nil {
		at = 1
	}
	out := make([]string, 0, len(args)+len(extra))
	out = append(out, args[:at]...)
	out = append(out, extra...)
	return append(out, args[at:]...)
}

func persistDir() string {
	d := filepath.Join(filepath.Dir(stateDir()), "persist")
	os.MkdirAll(d, 0o700)
	return d
}

func persistFile(id string) string { return filepath.Join(persistDir(), id+".json") }

func loadStates() []stateRec {
	out := []stateRec{} // non-nil so ls --json prints [] not null
	des, err := os.ReadDir(stateDir())
	if err != nil {
		return out
	}
	for _, de := range des {
		if !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(stateDir(), de.Name()))
		if err != nil {
			continue
		}
		var rec stateRec
		if json.Unmarshal(b, &rec) != nil {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// flagName strips leading dashes, returning "" for a non-flag token (so a bare
// command word is never mistaken for a flag).
func flagName(tok string) string {
	if !strings.HasPrefix(tok, "-") {
		return ""
	}
	name, _, _ := strings.Cut(strings.TrimLeft(tok, "-"), "=")
	return name
}

// isTshareFlag reports whether tok names one of tshare's own flags, so
// trailing-flag lifting only ever peels tshare flags off a command and never
// touches an app's options.
func isTshareFlag(tok string) bool {
	name := flagName(tok)
	if name == "" {
		return false
	}
	_, known := tshareFlags()[name]
	return known
}

// runValueFlag reports whether a tshare flag consumes the following token.
func runValueFlag(tok string) bool {
	return tshareFlags()[flagName(tok)]
}

// tshareInternalFlag reports whether a flag is one of the private --__ markers
// daemonize/resume pass to a child (never part of a persisted command line).
func tshareInternalFlag(tok string) bool {
	return strings.HasPrefix(flagName(tok), "__")
}

// launchFlags go on every front-end launch: detach, report as JSON, and leave
// out the terminal-only niceties (QR, clipboard, auto-opened pages).
var launchFlags = []string{"-b", "--json", "--no-qr", "--no-copy", "--no-open"}

// reservedFlags are the ones front ends set themselves; a caller passing them
// would break the launch (--quiet turns the JSON report into a bare URL).
var reservedFlags = map[string]bool{
	"b": true, "bg": true, "json": true, "quiet": true, "webwiz": true,
}

// launchShare starts a share in the background and returns its published state.
func launchShare(argv []string) (stateRec, error) {
	exe, err := os.Executable()
	if err != nil {
		return stateRec{}, err
	}
	// -b waits up to 60s for a slow start (a launched server, a big download)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, insertArgs(argv, launchFlags...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()

	var rec stateRec
	if i := bytes.IndexByte(out.Bytes(), '{'); i >= 0 {
		json.NewDecoder(bytes.NewReader(out.Bytes()[i:])).Decode(&rec)
	}
	if runErr == nil && rec.ID != "" {
		return rec, nil
	}
	return stateRec{}, launchError(errb.String(), out.String(), runErr)
}

// launchError keeps what a person needs to read: tshare's own message.
func launchError(stderr, stdout string, err error) error {
	for _, text := range []string{stderr, stdout} {
		var lines []string
		for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, strings.TrimPrefix(l, "tshare: "))
			}
		}
		if len(lines) > 0 {
			if len(lines) > 8 { // the tail is where the reason is
				lines = lines[len(lines)-8:]
			}
			return errors.New(strings.Join(lines, "\n"))
		}
	}
	if err != nil {
		return err
	}
	return errors.New("the share didn't report back (check: tshare ls)")
}

// expandHome turns "~/x" into the home directory path, as a shell would.
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// liveShares lists the shares that are actually running.
func liveShares() []stateRec {
	out := []stateRec{}
	for _, r := range loadStates() {
		if recAlive(r) {
			out = append(out, r)
		}
	}
	return out
}

func isPersisted(id string) bool { return fileExists(persistFile(id)) }

var shareIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$`)

// requireLive insists on the EXACT id of a running share. `tshare rm` also
// accepts prefixes and "all"/"--all", which a person types on purpose but a
// remote caller must never trigger by accident — one stray "a" would stop
// every share whose id starts with it.
func requireLive(id string) (stateRec, error) {
	if !shareIDRe.MatchString(id) {
		return stateRec{}, fmt.Errorf("%q is not a share id (see the list of shares)", id)
	}
	for _, r := range liveShares() {
		if r.ID == id {
			return r, nil
		}
	}
	return stateRec{}, fmt.Errorf("no running share has the id %q", id)
}

// stopShare stops one running share exactly as `tshare rm` does.
func stopShare(id string) error {
	if _, err := requireLive(id); err != nil {
		return err
	}
	_, err := runSelf(30*time.Second, "rm", id)
	return err
}

// updateShare changes a running share's options exactly as `tshare set` does.
func updateShare(id string, args []string) (string, error) {
	if _, err := requireLive(id); err != nil {
		return "", err
	}
	return runSelf(15*time.Second, append([]string{"set", id}, args...)...)
}

// shareInfo returns a running share's live stats as JSON.
func shareInfo(id string) (string, error) {
	if _, err := requireLive(id); err != nil {
		return "", err
	}
	return runSelf(15*time.Second, "info", id)
}

func runSelf(timeout time.Duration, args ...string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text == "" {
			return "", err
		}
		return "", errors.New(strings.TrimPrefix(text, "tshare: "))
	}
	return text, nil
}

// checkCallerArgs vets raw flags from outside (an MCP agent's extra_args): only
// tshare's own flags, never the private --__ markers, never the launch flags a
// front end owns, and every value-taking flag must have its value.
func checkCallerArgs(args []string) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			return fmt.Errorf("%q isn't a flag — give the file or folder as the path", a)
		}
		if !isTshareFlag(a) || tshareInternalFlag(a) {
			return fmt.Errorf("%s isn't a tshare option (see the options list)", a)
		}
		if reservedFlags[flagName(a)] {
			return fmt.Errorf("%s is set by the caller automatically", a)
		}
		if runValueFlag(a) && !strings.Contains(a, "=") {
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a value", a)
			}
			i++
		}
	}
	return nil
}

// tshare's own flags, derived from the flag definitions so they can never
// drift. The value is whether the flag consumes the next token: `--name demo`
// does, `--tmux` doesn't — read off each flag's Value as the flag package
// does. Hand-written copies of this list are how `tshare run -- cmd` used to
// mis-split a newly added flag.
var tshareFlags = sync.OnceValue(func() map[string]bool {
	m := make(map[string]bool, 128)
	if defineFlags == nil {
		return m
	}
	fs := flag.NewFlagSet("introspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	defineFlags(fs)
	fs.VisitAll(func(f *flag.Flag) {
		b, isBool := f.Value.(interface{ IsBoolFlag() bool })
		m[f.Name] = !(isBool && b.IsBoolFlag())
	})
	return m
})

// ---------------------------------------------------------------------------
// the built-in share engine: tshare with main.go alone. `tshare <file or
// folder>` serves it behind an unguessable path over Tailscale Funnel (-t
// tailnet-only, -l local network only, -p password) until Ctrl-C, and records
// itself like any share, so `tshare ls`, `rm` and `cleanup` see it. The full
// engine (share.go and the modules around it) replaces this when built in.

func builtinShare(args []string) {
	fs := flag.NewFlagSet("tshare", flag.ExitOnError)
	pw := fs.String("p", os.Getenv("TSHARE_PASSWORD"), "require this password (any username)")
	tailnet := fs.Bool("t", false, "tailnet only (tailscale serve), not the public internet")
	local := fs.Bool("l", false, "local network only: plain HTTP, no Tailscale")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "tshare — core build (main.go alone)\n\n"+
			"  tshare [-p password] [-t | -l] <file or folder>\n\n"+
			"Serves it behind an unguessable link over Tailscale Funnel until Ctrl-C.\n"+
			"Build with the other .go files for everything else tshare does.\n\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	root, err := filepath.Abs(fs.Arg(0))
	if err == nil {
		root, err = filepath.EvalSymlinks(root)
	}
	fi, serr := os.Stat(root)
	if err != nil || serr != nil {
		log.Fatalf("tshare: %s: no such file or folder", fs.Arg(0))
	}

	bind := "127.0.0.1:0" // funnel/serve reach us through tailscaled, over loopback
	if *local {
		bind = "0.0.0.0:0"
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	token := builtinToken(16)
	link, unmount, err := builtinPublish(*tailnet, *local, token, port)
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	if !fi.IsDir() {
		link += url.PathEscape(fi.Name())
	}

	id := builtinToken(6)
	mode := "dir"
	if !fi.IsDir() {
		mode = "file"
	}
	rec := stateRec{ID: id, PID: os.Getpid(), Token: token, Mode: mode, Title: fi.Name(), URL: link,
		Target: root, Tailnet: *tailnet, Local: *local, HTTPSPort: 443, Port: port,
		Password: *pw != "", Created: time.Now()}
	if err := writeJSON(stateFile(id), rec); err != nil {
		log.Printf("warn: %v", err)
	}
	srv := &http.Server{Handler: builtinHandler(root, fi.IsDir(), token, *pw, *local), ReadHeaderTimeout: 15 * time.Second}
	go srv.Serve(ln)
	fmt.Printf("\n  tshare · sharing %s\n  link   %s\n  id     %s · Ctrl-C to stop\n\n", root, link, id)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	unmount()
	os.Remove(stateFile(id))
	fmt.Println("  stopped")
}

// builtinPublish puts the share on Tailscale (or just the LAN) and returns its
// link and how to take it down again.
func builtinPublish(tailnet, local bool, token string, port int) (link string, unmount func(), err error) {
	if local {
		return fmt.Sprintf("http://%s:%d/%s/", builtinLANIP(), port, token), func() {}, nil
	}
	bin, err := exec.LookPath("tailscale")
	if err != nil {
		if mac := "/Applications/Tailscale.app/Contents/MacOS/Tailscale"; fileExists(mac) {
			bin, err = mac, nil
		} else {
			return "", nil, errors.New("tailscale not found — install it, or share on your LAN with -l")
		}
	}
	out, err := exec.Command(bin, "status", "--json").Output()
	var st struct{ Self struct{ DNSName string } }
	if err != nil || json.Unmarshal(out, &st) != nil || st.Self.DNSName == "" {
		return "", nil, errors.New("tailscale isn't running or has no MagicDNS name — or share on your LAN with -l")
	}
	verb := "funnel"
	if tailnet {
		verb = "serve"
	}
	if out, err := exec.Command(bin, verb, "--bg", "--https=443", "--set-path=/"+token,
		fmt.Sprintf("http://127.0.0.1:%d", port)).CombinedOutput(); err != nil {
		return "", nil, fmt.Errorf("tailscale %s failed: %s", verb, strings.TrimSpace(string(out)))
	}
	unmount = func() { exec.Command(bin, verb, "--https=443", "--set-path=/"+token, "off").Run() }
	return "https://" + strings.TrimSuffix(st.Self.DNSName, ".") + "/" + token + "/", unmount, nil
}

// builtinHandler serves one file, or a folder with listings. A direct (LAN)
// hit must carry the secret token; over funnel/serve, tailscaled has already
// matched and stripped it. Dotfiles are never listed or served, nothing
// outside the shared folder is reachable (symlinks included), and responses
// are sandboxed so a shared page can't run scripts.
func builtinHandler(root string, isDir bool, token, pw string, requireToken bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Robots-Tag", "noindex, nofollow")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "sandbox")
		p := r.URL.Path
		if rest, ok := strings.CutPrefix(p, "/"+token); ok && (rest == "" || rest[0] == '/') {
			p = rest
		} else if requireToken {
			http.NotFound(w, r)
			return
		}
		if pw != "" {
			if _, got, ok := r.BasicAuth(); !ok || subtle.ConstantTimeCompare([]byte(got), []byte(pw)) != 1 {
				h.Set("WWW-Authenticate", `Basic realm="tshare"`)
				http.Error(w, "password required", http.StatusUnauthorized)
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !isDir {
			builtinSendFile(w, r, root)
			return
		}
		rel := path.Clean("/" + p)
		for _, seg := range strings.Split(rel, "/") {
			if strings.HasPrefix(seg, ".") {
				http.NotFound(w, r)
				return
			}
		}
		real, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil || (real != root && !strings.HasPrefix(real, root+string(filepath.Separator))) {
			http.NotFound(w, r)
			return
		}
		fi, err := os.Stat(real)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if !fi.IsDir() {
			builtinSendFile(w, r, real)
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/") { // relative, so it's right under /<token>/ too
			h.Set("Location", path.Base(rel)+"/")
			w.WriteHeader(http.StatusMovedPermanently)
			return
		}
		builtinList(w, rel, real)
	})
}

func builtinSendFile(w http.ResponseWriter, r *http.Request, p string) {
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}

func builtinList(w http.ResponseWriter, rel, dir string) {
	des, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, "can't read folder", http.StatusInternalServerError)
		return
	}
	var b strings.Builder
	b.WriteString(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">` +
		`<title>` + html.EscapeString(rel) + `</title><style>body{font:15px/1.6 system-ui,sans-serif;max-width:760px;` +
		`margin:0 auto;padding:24px 18px}a{text-decoration:none}li{list-style:none;padding:4px 0}ul{padding:0}</style>` +
		`<h3>` + html.EscapeString(rel) + `</h3><ul>`)
	if rel != "/" {
		b.WriteString(`<li><a href="../">⬆ ..</a></li>`)
	}
	sort.Slice(des, func(i, j int) bool {
		if des[i].IsDir() != des[j].IsDir() {
			return des[i].IsDir()
		}
		return des[i].Name() < des[j].Name()
	})
	for _, de := range des {
		name := de.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		href, label := url.PathEscape(name), html.EscapeString(name)
		if de.IsDir() {
			href, label = href+"/", "📁 "+label+"/"
		}
		b.WriteString(`<li><a href="` + href + `">` + label + `</a></li>`)
	}
	b.WriteString(`</ul>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

func builtinToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n]
}

// builtinLANIP is this machine's address on the local network.
func builtinLANIP() string {
	conn, err := net.Dial("udp", "192.0.2.1:9") // no packets sent: just picks the route
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
