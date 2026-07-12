//go:build unix

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		ID: s.id, PID: os.Getpid(), Token: s.token, Mode: s.mode,
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
		if rec.Token == mount && pidAlive(rec.PID) {
			return true
		}
	}
	return false
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// ---------------------------------------------------------------------------
// background mode

func daemonize(s *share) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// re-exec with daemon markers (child sees --bg too, but daemonChild
	// short-circuits re-daemonizing, so flags and defaults stay identical)
	args := append([]string{}, os.Args[1:]...)
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
			args = append(args, "--filename", s.roots[0].Name)
		}
		if s.tmpFile != "" {
			args = append(args, "--__tmp", s.tmpFile)
		}
		if s.tmpDir != "" {
			args = append(args, "--__tmpdir", s.tmpDir)
		}
	}
	if s.cfg.encKeyHex != "" { // hand the inbox key to the child so it stays stable
		args = append(args, "--__enckey", s.cfg.encKeyHex)
	}
	if s.gameSid != "" { // hand the game session id to the child so its join link matches what we advertise
		args = append(args, "--__gamesid", s.gameSid)
	}
	args = append(args, "--__daemon", "--__id", s.id)

	logDir := filepath.Join(filepath.Dir(stateDir()), "logs")
	os.MkdirAll(logDir, 0o700)
	lf, err := os.OpenFile(filepath.Join(logDir, s.id+".log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer lf.Close()

	cmd := exec.Command(exe, args...)
	cmd.Stdout = lf
	cmd.Stderr = lf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	// wait for the child to publish its state (max ~8s)
	sf := stateFile(s.id)
	for i := 0; i < 80; i++ {
		time.Sleep(100 * time.Millisecond)
		b, err := os.ReadFile(sf)
		if err != nil {
			if !pidAlive(pid) {
				lb, _ := os.ReadFile(filepath.Join(logDir, s.id+".log"))
				return fmt.Errorf("background share failed to start:\n%s", string(lb))
			}
			continue
		}
		var rec stateRec
		if json.Unmarshal(b, &rec) != nil || rec.URL == "" {
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
	skip := map[string]bool{"--__daemon": true, "--__id": true, "--__tmp": true, "--__tmpdir": true, "--__enckey": true, "--__gamesid": true}
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
	rec := persistRec{ID: s.id, Args: args, Cwd: cwd, Created: time.Now()}
	return writeJSON(persistFile(s.id), rec)
}

func cmdResume(args []string) {
	des, err := os.ReadDir(persistDir())
	if err != nil || len(des) == 0 {
		fmt.Println("no persisted shares to resume")
		return
	}
	live := map[string]bool{}
	for _, r := range loadStates() {
		if pidAlive(r.PID) {
			live[r.ID] = true
		}
	}
	exe, _ := os.Executable()
	n := 0
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
		ra := append([]string{}, rec.Args...)
		if !hasArg(ra, "-b") && !hasArg(ra, "--bg") {
			ra = append(ra, "-b") // resume detached
		}
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
