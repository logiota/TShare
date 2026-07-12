//go:build unix

package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
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

// senderReq: the auto-opened local sender tab authenticates with a per-share
// secret key (bypasses the Basic-Auth password, never counts as a download).
func (s *share) senderReq(r *http.Request) bool {
	return s.senderKey != "" &&
		subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("k")), []byte(s.senderKey)) == 1
}

// handleGameIce serves the RTCPeerConnection iceServers config to a GIGA-NET/1-L
// game page (same-origin, token/password-gated like everything else). Over
// funnel/tailnet it returns the STUN/TURN config so peers on different networks
// can hole-punch; in --local mode it returns [] so LAN play stays pure and
// instant (host candidates only — nothing reaches a public STUN server).
func (s *share) handleGameIce(w *respRec, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body := "[]"
	if !s.cfg.Local {
		body = string(s.iceJSON())
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	io.WriteString(w, body)
}

// iceJSON builds the RTCPeerConnection iceServers config from --stun/--turn.
func (s *share) iceJSON() template.JS {
	type entry struct {
		URLs       []string `json:"urls"`
		Username   string   `json:"username,omitempty"`
		Credential string   `json:"credential,omitempty"`
	}
	var servers []entry
	var stuns []string
	for _, u := range strings.Split(s.cfg.STUN, ",") {
		if u = strings.TrimSpace(u); u != "" {
			stuns = append(stuns, u)
		}
	}
	if len(stuns) > 0 {
		servers = append(servers, entry{URLs: stuns})
	}
	if t := strings.TrimSpace(s.cfg.TURN); t != "" {
		servers = append(servers, entry{URLs: []string{t}, Username: s.cfg.TURNUser, Credential: s.cfg.TURNPass})
	}
	b, _ := json.Marshal(servers)
	return template.JS(b)
}

// handleRTC serves the signaling endpoints under __rtc/. Receiver-side calls
// arrive through the normal token+password gate; sender-tab calls carry ?k=.
func (s *share) handleRTC(w *respRec, r *http.Request, ep string) {
	if s.hub == nil {
		http.NotFound(w, r)
		return
	}
	q := r.URL.Query()
	jsonOK := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(v)
		w.Write(b)
	}
	role := func(k string) string { // constrain to a|b
		if v := q.Get(k); v == "a" || v == "b" {
			return v
		}
		return ""
	}
	switch {
	case ep == "msg" && r.Method == http.MethodPost:
		sid, from := q.Get("sid"), role("from")
		if !validSID(sid) || from == "" {
			http.Error(w, "bad sid/from", http.StatusBadRequest)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			http.Error(w, "message too large", http.StatusRequestEntityTooLarge)
			return
		}
		to := "a"
		if from == "a" {
			to = "b"
		}
		if err := s.hub.post(sid, to, body); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		jsonOK(map[string]any{"ok": true})
	case ep == "msg":
		sid, as := q.Get("sid"), role("as")
		if !validSID(sid) || as == "" {
			http.Error(w, "bad sid/as", http.StatusBadRequest)
			return
		}
		if msg := s.hub.take(r.Context(), sid, as, q.Get("wait") == "1"); msg != nil {
			w.Header().Set("Content-Type", "application/json")
			w.Write(msg)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case ep == "hello" && r.Method == http.MethodPost:
		sid := q.Get("sid")
		if !validSID(sid) {
			http.Error(w, "bad sid", http.StatusBadRequest)
			return
		}
		// wanted file (multi-file shares): must be a flat, sane name that this
		// share actually offers — never a path.
		file := q.Get("f")
		if file != "" {
			if file != sanitizeName(file) || strings.ContainsAny(file, "/\\") {
				http.Error(w, "bad file", http.StatusBadRequest)
				return
			}
			ok := false
			for _, f := range s.p2pFiles() {
				if f.Name == file {
					ok = true
					break
				}
			}
			if !ok {
				http.Error(w, "unknown file", http.StatusNotFound)
				return
			}
		}
		s.hub.announce(sid, file)
		jsonOK(map[string]any{"ok": true})
	case ep == "next":
		if !s.senderReq(r) {
			http.Error(w, "403", http.StatusForbidden)
			return
		}
		// the connected poll itself is proof of life — beats survive Safari's
		// background-tab timer throttling, which stalls setInterval heartbeats
		s.hub.senderBeat()
		s.hub.mu.Lock()
		s.hub.senderPolls++
		s.hub.mu.Unlock()
		sid, file := s.hub.next(r.Context(), q.Get("wait") == "1")
		s.hub.mu.Lock()
		s.hub.senderPolls--
		s.hub.mu.Unlock()
		s.hub.senderBeat()
		if sid != "" {
			jsonOK(map[string]any{"sid": sid, "file": file})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case ep == "presence" && r.Method == http.MethodPost:
		if s.senderReq(r) {
			s.hub.senderBeat()
		} else if ro := role("as"); ro != "" {
			s.hub.beat(ro)
		}
		jsonOK(map[string]any{"ok": true})
	case ep == "presence":
		jsonOK(map[string]any{"online": s.hub.senderOnline()})
	case ep == "claim":
		ro, ok := s.hub.claim()
		if !ok {
			http.Error(w, "call is full (two participants)", http.StatusConflict)
			return
		}
		jsonOK(map[string]any{"role": ro})
	case ep == "done" && r.Method == http.MethodPost:
		if s.senderKey != "" { // p2p transfer completed → counts as a download
			s.countDownload()
			if !s.cfg.Quiet {
				log.Printf("  ⚡ p2p transfer complete (%s)", q.Get("sid"))
			}
		}
		jsonOK(map[string]any{"ok": true})
	default:
		http.NotFound(w, r)
	}
}
