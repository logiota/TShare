//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// browser WebRTC: P2P direct transfer (--p2p) + built-in 1:1 call (--call)
//
// The Go binary stays stdlib-only: all WebRTC runs in the browsers. tshare is
// the token-gated signaling relay (tiny JSON mailboxes with HTTP long-poll)
// plus the static pages. For --p2p the SENDER side is an auto-opened local
// browser tab that streams the file from loopback into a DataChannel; the
// receiver's browser hole-punches a direct connection (STUN → works through
// most NATs and many CGNATs), so the bytes never ride the funnel relay — that
// is the performance win. When ICE fails, the normal HTTPS download through
// the funnel is one click away. Optional TURN (--turn) guarantees delivery.

type rtcHub struct {
	mu          sync.Mutex
	sessions    map[string]*rtcSess
	pending     []rtcPend            // receivers waiting for the sender tab (sid + wanted file)
	pendCh      chan struct{}        // signaled when pending grows
	senderSeen  time.Time            // --p2p sender-tab heartbeat
	senderPolls int                  // open sender long-polls (a connected poll = alive)
	claims      map[string]time.Time // --call: role → last heartbeat
	lastGC      time.Time
}

type rtcSess struct {
	touched time.Time
	q       map[string][][]byte      // per-recipient FIFO ("a" / "b")
	ch      map[string]chan struct{} // wake channels for long-pollers
}

func newRTCHub() *rtcHub {
	return &rtcHub{sessions: map[string]*rtcSess{}, pendCh: make(chan struct{}, 1),
		claims: map[string]time.Time{}}
}

func validSID(sid string) bool {
	if len(sid) < 4 || len(sid) > 64 {
		return false
	}
	for _, r := range sid {
		if !(r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// locked helpers -------------------------------------------------------------

func (h *rtcHub) gcLocked() {
	if time.Since(h.lastGC) < 30*time.Second {
		return
	}
	h.lastGC = time.Now()
	for sid, s := range h.sessions {
		if time.Since(s.touched) > 10*time.Minute {
			delete(h.sessions, sid)
		}
	}
}

func (h *rtcHub) sessLocked(sid string) *rtcSess {
	s := h.sessions[sid]
	if s == nil {
		s = &rtcSess{q: map[string][][]byte{}, ch: map[string]chan struct{}{
			"a": make(chan struct{}, 1), "b": make(chan struct{}, 1)}}
		h.sessions[sid] = s
	}
	s.touched = time.Now()
	return s
}

// post delivers one signaling message to `to` ("a"|"b") in session sid.
func (h *rtcHub) post(sid, to string, msg []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.gcLocked()
	if len(h.sessions) > 64 && h.sessions[sid] == nil {
		return errors.New("too many sessions")
	}
	s := h.sessLocked(sid)
	if len(s.q[to]) > 512 {
		return errors.New("queue full")
	}
	s.q[to] = append(s.q[to], msg)
	select {
	case s.ch[to] <- struct{}{}:
	default:
	}
	return nil
}

// take pops the oldest message for `as`, long-polling up to 25s when wait.
func (h *rtcHub) take(ctx context.Context, sid, as string, wait bool) []byte {
	deadline := time.After(25 * time.Second)
	for {
		h.mu.Lock()
		s := h.sessLocked(sid)
		if q := s.q[as]; len(q) > 0 {
			msg := q[0]
			s.q[as] = q[1:]
			h.mu.Unlock()
			return msg
		}
		ch := s.ch[as]
		h.mu.Unlock()
		if !wait {
			return nil
		}
		select {
		case <-ch:
		case <-deadline:
			return nil
		case <-ctx.Done():
			return nil
		}
	}
}

// rtcPend is a receiver waiting for the sender tab: its session id and which
// file it wants (multi-file --p2p shares, e.g. RAR volumes).
type rtcPend struct{ sid, file string }

// announce / next: receivers announce their sid (+wanted file); the sender
// tab pops them.
func (h *rtcHub) announce(sid, file string) {
	h.mu.Lock()
	h.pending = append(h.pending, rtcPend{sid, file})
	h.sessLocked(sid)
	h.mu.Unlock()
	select {
	case h.pendCh <- struct{}{}:
	default:
	}
}

func (h *rtcHub) next(ctx context.Context, wait bool) (string, string) {
	deadline := time.After(25 * time.Second)
	for {
		h.mu.Lock()
		if len(h.pending) > 0 {
			p := h.pending[0]
			h.pending = h.pending[1:]
			h.mu.Unlock()
			return p.sid, p.file
		}
		h.mu.Unlock()
		if !wait {
			return "", ""
		}
		select {
		case <-h.pendCh:
		case <-deadline:
			return "", ""
		case <-ctx.Done():
			return "", ""
		}
	}
}

// claim hands out the two --call roles; a role is reclaimable once its peer
// stops heartbeating for 15s (page closed), so a dropped caller can rejoin.
func (h *rtcHub) claim() (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, role := range []string{"a", "b"} {
		if time.Since(h.claims[role]) > 15*time.Second {
			h.claims[role] = time.Now()
			return role, true
		}
	}
	return "", false
}

func (h *rtcHub) beat(role string) {
	h.mu.Lock()
	if _, ok := h.claims[role]; ok || role == "a" || role == "b" {
		h.claims[role] = time.Now()
	}
	h.mu.Unlock()
}

func (h *rtcHub) senderBeat() { h.mu.Lock(); h.senderSeen = time.Now(); h.mu.Unlock() }

// senderOnline is deliberately generous: Safari throttles or suspends timers
// in background tabs, so explicit heartbeats can stall while the tab is still
// perfectly able to serve (its chained long-poll is network-event driven and
// keeps running). An open long-poll counts as a live beat (see handleRTC), and
// the window is a full minute so a throttled-but-alive tab stays "online".
func (h *rtcHub) senderOnline() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.senderPolls > 0 || time.Since(h.senderSeen) < 60*time.Second
}

// rarSplit packs root into RAR volumes of --rar-size bytes under
// ~/.tshare/rar/<id>/ and returns that folder. Volume size is passed in
// explicit bytes (-v<N>b) so it means the same thing on every rar version.
// -m0 stores without compression: the point is chunking, not shrinking.
func rarSplit(c *config, root rootEnt, id string) (string, error) {
	bin, err := exec.LookPath("rar")
	if err != nil {
		return "", errors.New("rar not found — install it first (brew install rar) to use --rar")
	}
	volBytes, err := parseSize(c.RarSize)
	if err != nil || volBytes < 1<<20 {
		return "", errors.New("--rar-size needs a size ≥ 1M, e.g. 1400M")
	}
	dir := filepath.Join(filepath.Dir(stateDir()), "rar", id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	stem := strings.TrimSuffix(root.Name, filepath.Ext(root.Name))
	if stem = sanitizeName(stem); stem == "" {
		stem = "archive"
	}
	fmt.Fprintf(os.Stderr, "  ▶ rar: splitting %s into %s volumes (store mode)…\n", root.Name, c.RarSize)
	args := []string{"a", fmt.Sprintf("-v%db", volBytes), "-ep1", "-r", "-m0", "-y",
		filepath.Join(dir, stem+".rar"), root.Abs}
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("rar failed: %w", err)
	}
	des, err := os.ReadDir(dir)
	if err != nil || len(des) == 0 {
		os.RemoveAll(dir)
		return "", errors.New("rar produced no volumes")
	}
	fmt.Fprintf(os.Stderr, "  ✓ %d volume(s) — receivers extract with unrar / 7-Zip / iZip (open part1)\n", len(des))
	return dir, nil
}

// p2pFiles lists what a --p2p share offers: the single file, or the flat
// regular files of a folder share (RAR volumes), sorted by name.
func (s *share) p2pFiles() []rootEnt {
	if s.mode == "file" {
		return []rootEnt{s.roots[0]}
	}
	des, err := os.ReadDir(s.roots[0].Abs)
	if err != nil {
		return nil
	}
	var out []rootEnt
	for _, de := range des {
		if de.IsDir() || strings.HasPrefix(de.Name(), ".") {
			continue
		}
		if fi, err := de.Info(); err == nil {
			out = append(out, rootEnt{Name: de.Name(), Abs: filepath.Join(s.roots[0].Abs, de.Name()), Size: fi.Size()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
