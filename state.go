//go:build unix

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// state files (~/.tshare/shares/<id>.json)

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

func (s *share) stateRec(port int) stateRec {
	target := s.describe()
	var procs []procRec
	for _, p := range s.procs {
		procs = append(procs, procRec{Pid: p.pid(), Tmux: p.tmuxWin})
	}
	gameJoin, gameHost := s.gameLinks()
	return stateRec{
		ID: s.id, PID: os.Getpid(), Token: s.token, Mode: s.mode, Title: s.title(),
		URL: s.prettyURL(), Target: target, Tailnet: s.cfg.Tailnet, Local: s.cfg.Local,
		HTTPSPort: s.cfg.HTTPSPort, Port: port, Password: s.getPassword() != "",
		MaxDL: s.maxDL.Load(), Downloads: s.dl.Load(), Uploads: s.upCount.Load(),
		Created: s.createdAt, Expires: s.getExpires(),
		Procs: procs, RootMount: s.mtRootMounted,
		GameJoin: gameJoin, GameHost: gameHost,
	}
}

func (s *share) saveState(port int) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.lastPort = port
	err := writeJSON(stateFile(s.id), s.stateRec(port))
	s.lastStateWrite = time.Now()
	s.stateDirty = false
	return err
}

// updateState keeps the on-disk state fresh for `ls`/`info` but throttles the
// actual write to at most once/second; the rest is coalesced and flushed by the
// periodic flusher / on shutdown. This keeps disk I/O off the download hot path.
func (s *share) updateState() {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.stateDirty = true
	if time.Since(s.lastStateWrite) >= time.Second {
		s.flushStateLocked()
	}
}

// flushStateLocked writes the state file; caller must hold stateMu.
func (s *share) flushStateLocked() {
	if !s.stateDirty {
		return
	}
	writeJSON(stateFile(s.id), s.stateRec(s.lastPort))
	s.lastStateWrite = time.Now()
	s.stateDirty = false
}

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

func nameInUse(mount string) bool {
	des, err := os.ReadDir(stateDir())
	if err != nil {
		return false
	}
	for _, de := range des {
		var rec stateRec
		b, err := os.ReadFile(filepath.Join(stateDir(), de.Name()))
		if err != nil || json.Unmarshal(b, &rec) != nil {
			continue
		}
		if rec.Token == mount && recAlive(rec) {
			return true
		}
	}
	return false
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

// ---------------------------------------------------------------------------
// background mode

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

func daemonize(s *share) error {
	if os.Getenv(daemonEnv) != "" {
		return errors.New("internal: a background child tried to background itself again (daemon markers lost) — refusing")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// re-exec with daemon markers (child sees --bg too, but daemonChild
	// short-circuits re-daemonizing, so flags and defaults stay identical)
	args := append([]string{}, os.Args[1:]...)
	var extra []string
	if s.tmpRoot != "" {
		// stdin/yt input was already produced by THIS parent — the child can't
		// re-read stdin or re-download, so hand it the materialized path and
		// strip the input-producing flags so the child just serves the file.
		args = stripYtFlags(args)
		for i, a := range args {
			if a == s.srcArg {
				args[i] = s.tmpRoot
				break
			}
		}
		if s.mode == "file" {
			extra = append(extra, "--filename", s.roots[0].Name)
		}
		if s.tmpFile != "" {
			extra = append(extra, "--__tmp", s.tmpFile)
		}
		if s.tmpDir != "" {
			extra = append(extra, "--__tmpdir", s.tmpDir)
		}
	}
	if s.cfg.encKeyHex != "" { // hand the inbox key to the child so it stays stable
		extra = append(extra, "--__enckey", s.cfg.encKeyHex)
	}
	if s.gameSid != "" { // hand the game session id to the child so its join link matches what we advertise
		extra = append(extra, "--__gamesid", s.gameSid)
	}
	args = insertArgs(args, append(extra, "--__daemon", "--__id", s.id)...)

	logDir := filepath.Join(filepath.Dir(stateDir()), "logs")
	os.MkdirAll(logDir, 0o700)
	lf, err := os.OpenFile(filepath.Join(logDir, s.id+".log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()

	// A crashed predecessor with this id may have left its state file behind;
	// drop it so it can't be mistaken for the new child's.
	os.Remove(stateFile(s.id))

	cmd := exec.Command(exe, args...)
	cmd.Env = append(os.Environ(), daemonEnv+"=1")
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	// Wait for the child to publish its state. Bounded generously (60s) because
	// a share that launches a server first (run/host/--room/--kuma) only writes
	// state once that server is up; a child that dies is detected immediately
	// below, so a healthy-but-slow start is never reported as a failure.
	sf := stateFile(s.id)
	for i := 0; i < 600; i++ {
		time.Sleep(100 * time.Millisecond)
		b, err := os.ReadFile(sf)
		var rec stateRec
		// only state published by THIS child means it's up — a leftover file
		// from an earlier run of the same id must not read as success
		if err != nil || json.Unmarshal(b, &rec) != nil || rec.PID != pid || rec.URL == "" {
			if !pidAlive(pid) {
				lb, _ := os.ReadFile(filepath.Join(logDir, s.id+".log"))
				return fmt.Errorf("background share failed to start:\n%s", string(lb))
			}
			continue
		}
		if s.cfg.Quiet {
			if rec.GameJoin != "" { // game share: the JOIN link is the artifact you pipe/send
				fmt.Println(rec.GameJoin)
			} else {
				fmt.Println(rec.URL)
			}
		} else if s.cfg.JSON {
			fmt.Println(string(b)) // state JSON includes game_join/game_host for -g shares
		} else {
			fmt.Printf("\n  ✓ sharing in background  (id %s, pid %d)\n", rec.ID, pid)
			fmt.Printf("  link     %s\n", rec.URL)
			if rec.GameJoin != "" {
				fmt.Printf("  🎮 join  %s   ← send THIS to the other player\n", rec.GameJoin)
				fmt.Printf("  🎮 host  %s\n", rec.GameHost)
			}
			if !rec.Expires.IsZero() {
				fmt.Printf("  expires  %s (use -e never to keep)\n", rec.Expires.Format("Jan 2 15:04"))
			}
			fmt.Printf("  log      %s\n", filepath.Join(logDir, s.id+".log"))
			fmt.Printf("  stop     tshare rm %s\n\n", rec.ID)
		}
		if rec.GameJoin != "" {
			linkExtras(s.cfg, rec.GameJoin) // clipboard/QR get the join link, matching foreground -g
			// mirror foreground auto-open: the daemon child never opens a browser, so the parent does
			if s.cfg.NoOpen {
				fmt.Fprintf(os.Stderr, "  🎮 open this on the host machine: %s\n", rec.GameHost)
			} else {
				fmt.Fprintf(os.Stderr, "  🎮 host page opened — send the join link (already on your clipboard)\n")
				openBrowser(rec.GameHost)
			}
		} else {
			linkExtras(s.cfg, rec.URL)
		}
		return nil
	}
	return errors.New("timed out waiting for background share (check tshare ls / logs)")
}

// ---------------------------------------------------------------------------
// #84 persist & resume across reboot

type persistRec struct {
	ID      string    `json:"id"`
	Args    []string  `json:"args"`
	Cwd     string    `json:"cwd"`
	Created time.Time `json:"created"`
	Token   string    `json:"token,omitempty"`   // the secret path — replayed so links survive the restart
	Expires time.Time `json:"expires,omitempty"` // absolute deadline — replayed so a restart doesn't extend it
	Port    int       `json:"port,omitempty"`    // backend port — replayed when free, so LAN links stay identical too
}

// rePersist refreshes a live share's resume record (new expiry, new password
// state) so a restart restores what the share is NOW, not what it was at start.
func (s *share) rePersist() {
	if !s.cfg.Persist {
		return
	}
	if err := savePersist(s); err != nil && !s.cfg.Quiet {
		log.Printf("warn: could not refresh resume record: %v", err)
	}
}

func persistDir() string {
	d := filepath.Join(filepath.Dir(stateDir()), "persist")
	os.MkdirAll(d, 0o700)
	return d
}

func persistFile(id string) string { return filepath.Join(persistDir(), id+".json") }

func savePersist(s *share) error {
	if s.tmpRoot != "" || s.grow != nil {
		return errors.New("can't persist a stdin/stream/downloaded share")
	}
	cwd, _ := os.Getwd()
	// strip daemon-internal flags; keep --persist so a resumed share re-persists.
	// --__gamesid is stripped here and re-appended below so exactly one (the live
	// session id) survives — resume then reuses it, keeping distributed join links valid.
	var args []string
	skip := map[string]bool{"--__daemon": true, "--__id": true, "--__tmp": true, "--__tmpdir": true,
		"--__enckey": true, "--__gamesid": true, "--__token": true, "--__expires": true,
		"--__bindport": true}
	for i := 0; i < len(os.Args[1:]); i++ {
		a := os.Args[1:][i]
		if skip[a] {
			if a != "--__daemon" {
				i++ // also skip its value
			}
			continue
		}
		args = append(args, a)
	}
	if s.gameSid != "" { // pin the session id so `tshare resume` doesn't re-mint one and orphan links already shared
		args = append(args, "--__gamesid", s.gameSid)
	}
	s.stateMu.Lock()
	port := s.lastPort
	s.stateMu.Unlock()
	rec := persistRec{ID: s.id, Args: args, Cwd: cwd, Created: time.Now(),
		Token: s.token, Expires: s.getExpires(), Port: port}
	return writeJSON(persistFile(s.id), rec)
}

func init() { register(cmdResume, "resume") }

func cmdResume(args []string) {
	des, err := os.ReadDir(persistDir())
	if err != nil || len(des) == 0 {
		fmt.Println("no persisted shares to resume")
		return
	}
	live := map[string]bool{}
	for _, r := range loadStates() {
		if recAlive(r) { // boot-aware: a pre-reboot record is dead, pid or not
			live[r.ID] = true
		}
	}
	// read every record first, so we know whether to wait for tailscale at all
	var recs []persistRec
	for _, de := range des {
		if !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		var rec persistRec
		b, err := os.ReadFile(filepath.Join(persistDir(), de.Name()))
		if err != nil || json.Unmarshal(b, &rec) != nil {
			continue
		}
		if live[rec.ID] {
			continue // already running
		}
		// a share whose deadline passed while we were off should stay gone
		if !rec.Expires.IsZero() && time.Now().After(rec.Expires) {
			os.Remove(persistFile(rec.ID))
			fmt.Printf("  ⌛ %s expired while offline — record dropped\n", rec.ID)
			continue
		}
		// a live share may already hold this record's name/token (e.g. it was
		// resumed earlier under a different id) — don't start a duplicate.
		if name := persistName(rec.Args); name != "" && nameInUse(name) {
			continue
		}
		// A share killed uncleanly (crash, SIGKILL) leaves its managed servers
		// orphaned — still holding the very ports the resumed share needs.
		if b, err := os.ReadFile(stateFile(rec.ID)); err == nil {
			var old stateRec
			if json.Unmarshal(b, &old) == nil && !recAlive(old) {
				reapProcs(old.Procs, syscall.SIGTERM)
				os.Remove(stateFile(rec.ID))
			}
		}
		recs = append(recs, rec)
	}
	if len(recs) == 0 {
		fmt.Println("resumed 0 share(s)")
		return
	}
	// At login (launchd) we can easily beat tailscaled to the punch, and a
	// funnel/serve share started too early dies with "tailscale not ready".
	for _, rec := range recs {
		if !hasArg(rec.Args, "-l") && !hasArg(rec.Args, "--local") {
			waitTailscale(2 * time.Minute)
			break
		}
	}

	exe, _ := os.Executable()
	n := 0
	for _, rec := range recs {
		ra := append([]string{}, rec.Args...)
		var extra []string
		if !hasArg(ra, "-b") && !hasArg(ra, "--bg") {
			extra = append(extra, "-b") // resume detached
		}
		if !hasArg(ra, "--__id") {
			extra = append(extra, "--__id", rec.ID) // reuse the persist id so resume is idempotent
		}
		// replay the share's identity: same secret path, same deadline — the
		// whole point of --persist is that the link you handed out still works.
		if rec.Token != "" && !hasArg(ra, "--__token") {
			extra = append(extra, "--__token", rec.Token)
		}
		if !rec.Expires.IsZero() && !hasArg(ra, "--__expires") {
			extra = append(extra, "--__expires", rec.Expires.Format(time.RFC3339))
		}
		// Reuse the same backend port, so a --local link (which carries the
		// port) also comes back unchanged. --__bindport rather than --port,
		// because in run/host mode --port means the UPSTREAM server's port.
		if rec.Port > 0 && !hasArg(ra, "--__bindport") {
			extra = append(extra, "--__bindport", strconv.Itoa(rec.Port))
		}
		ra = insertArgs(ra, extra...)
		cmd := exec.Command(exe, ra...)
		cmd.Dir = rec.Cwd
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Printf("  ✗ %s: %v\n", rec.ID, err)
			continue
		}
		n++
	}
	fmt.Printf("resumed %d share(s)\n", n)
}

// waitTailscale blocks until tailscaled is up with a MagicDNS name, or limit
// passes. Resuming at boot/login otherwise races the daemon and loses.
func waitTailscale(limit time.Duration) {
	c := defaultConfig()
	ready := func() bool {
		ts, err := tsStatus(c)
		return err == nil && ts.Self.DNSName != ""
	}
	if ready() {
		return
	}
	fmt.Printf("  … waiting for tailscale (up to %s)\n", limit)
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		if ready() {
			fmt.Println("  ✓ tailscale ready")
			return
		}
	}
	fmt.Println("  ⚠ tailscale still not ready — resuming anyway")
}

// persistName extracts the --name/-n token from a persisted record's args, if
// any, so resume can detect that the name is already served by a live share.
func persistName(args []string) string {
	for i, a := range args {
		if (a == "--name" || a == "-n") && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "--name=") {
			return strings.TrimPrefix(a, "--name=")
		}
	}
	return ""
}
