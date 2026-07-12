//go:build unix

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// share setup

type rootEnt struct {
	Name  string // public name (basename), "" never
	Abs   string // absolute path
	IsDir bool
	Size  int64
}

type share struct {
	cfg       *config
	id        string
	token     string // mount path segment (token or vanity name)
	mode      string // "file" | "dir" | "multi" | "inbox" | "site"
	roots     []rootEnt
	siteIndex string // default document for a "site" share (index.html)
	gameSid   string // --gamelink: pre-minted GIGA-NET/1-L session id baked into the printed links
	upDir     string // where uploads land
	baseURL   string // https://host[:p]/<token>  (funnel/tailnet)
	lanURL    string // http://<lan-ip>:<port>/<token>  (direct LAN, if enabled)
	maxUp     int64
	srcArg    string // the original input token in argv ("-" or a URL) for bg re-exec
	tmpRoot   string // path the bg child should serve (file or dir)
	tmpFile   string // temp file to delete on exit
	tmpDir    string // temp dir to delete on exit (yt-dlp / playlist)
	ctlPath   string // unix control socket (tshare set / info)
	createdAt time.Time

	// runtime-mutable via `tshare set` (mu guards password & expiresAt;
	// lock order: stateMu before mu — never call updateState holding mu)
	mu        sync.RWMutex
	password  string
	expiresAt time.Time
	maxDL     atomic.Int64

	dl             atomic.Int64
	upCount        atomic.Int64
	shutdown       chan string
	stateMu        sync.Mutex
	lastPort       int
	lastStateWrite time.Time // throttle for state-file writes
	stateDirty     bool
	probeMu        sync.Mutex
	lastProbe      time.Time
	probeHeld      int
	reportMu       sync.Mutex // ⚑ report button: throttle owner notifications
	lastReport     time.Time

	maxBytes      int64        // #13: stop after this many bytes served (0 = ∞)
	bytesServed   atomic.Int64 // cumulative response bytes for the byte cap
	blackhole     bool         // -i: discard uploaded bytes (throughput sink, nothing on disk)
	minFree       int64        // refuse uploads when free disk bytes fall below this (0 = off)
	limiter       *rateLimiter // --max-rate: shared token bucket throttling served bytes (nil = off)
	viewers       atomic.Int64 // #61: in-flight viewers (presence)
	encKey        []byte       // #10: AES-256 key for at-rest inbox encryption
	grow          *growing     // #49: progressive/live source still being written
	ytPend        *ytPending   // yt-dlp download still running: hold visitors until ready
	afterAnnounce func()       // run once after the link/QR is printed (e.g. start the yt-dlp download)

	cpCmd   *exec.Cmd              // copyparty subprocess (folder engine), if used
	cpProxy *httputil.ReverseProxy // reverse proxy to copyparty on loopback
	cpPort  int

	srvProxy *httputil.ReverseProxy // -s: reverse proxy to a user-run server
	srvURL   string                 // its target URL (for display)

	roomName      string // --room: MiroTalk room id
	roomURL       string // --room: full MiroTalk join URL
	roomLocal     bool   // --room: using the local MiroTalk install
	kuma          bool   // --kuma: exposing Uptime Kuma at the funnel root
	kumaURL       string // the root dashboard URL
	mtRootMounted bool   // we mounted the funnel/serve ROOT path → unmount on exit

	procs []*serverProc // managed local servers we launched (run/host/room) — stopped on exit

	senderKey string  // --p2p: secret that authenticates the local sender tab
	hub       *rtcHub // --p2p / --call: in-memory WebRTC signaling relay
	jobs      *jobHub // --hub: web-grab job registry
}

func (s *share) getPassword() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.password
}

func (s *share) getExpires() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.expiresAt
}

func (s *share) expired() bool {
	t := s.getExpires()
	return !t.IsZero() && time.Now().After(t)
}

// doExtend pushes the expiry out. An empty spec or "double" DOUBLES the time
// remaining; any other value is parsed as a duration and added to the current
// expiry. A share that never expires has nothing to extend. Returns a human
// note for the caller to surface; safe to call without holding s.mu.
func (s *share) doExtend(spec string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expiresAt.IsZero() {
		return "", errors.New("share never expires — nothing to extend")
	}
	if spec == "" || spec == "double" {
		remaining := time.Until(s.expiresAt)
		if remaining <= 0 {
			return "", errors.New("share is already expiring — extend by an explicit duration instead")
		}
		s.expiresAt = s.expiresAt.Add(remaining) // +remaining ⇒ double the time left
		return "expiry doubled → " + s.expiresAt.Format("Jan 2 15:04"), nil
	}
	d, err := parseDuration(spec)
	if err != nil || d <= 0 {
		return "", errors.New("extend needs a positive duration (e.g. 2d) or nothing to double")
	}
	s.expiresAt = s.expiresAt.Add(d) // push the existing expiry out by d
	return "expiry +" + spec + " → " + s.expiresAt.Format("Jan 2 15:04"), nil
}

func runShare(c *config) error {
	if c.HTTPSPort != 443 && c.HTTPSPort != 8443 && c.HTTPSPort != 10000 {
		return errors.New("--https-port must be 443, 8443 or 10000")
	}
	if c.Name != "" && !validSlug(c.Name) {
		return errors.New("--name may contain only letters, digits, dot, dash, underscore")
	}
	if c.Upload && c.Zip {
		return errors.New("-u and -z don't combine")
	}
	// links default to a 15-day lifetime so forgotten public links don't
	// live forever; any explicit -e (including "never") overrides, and a
	// running share can be changed later: tshare set <id> -e <dur|never>.
	// --gamelink is sugar: a --site --allow-upload share of the game page, plus
	// a pre-minted GIGA-NET/1-L session — the join link is printed/copied and
	// this machine auto-opens the page in host mode (#gnhost), so starting a
	// multiplayer game is one command and zero clicks.
	if c.GameLink {
		c.Site = true
		c.AllowUpload = true
	}

	// Websites and the hub are long-term by nature, so they default to never.
	if !c.ExpiresSet && c.Expires == 0 && !c.Site && !c.Hub {
		c.Expires = 15 * 24 * time.Hour
	}

	// optional org policy (config-file only; #186). Absent by default — only a
	// [policy] section activates caps. Applied at share-creation time.
	if !c.NoConf {
		if pol := loadPolicy(configPath()); pol.active() {
			if pol.requirePw && c.Password == "" {
				return errors.New("config policy requires a password — pass -p (or set TSHARE_PASSWORD)")
			}
			if pol.maxExpiresSet && (c.Expires == 0 || c.Expires > pol.maxExpires) {
				c.Expires, c.ExpiresSet = pol.maxExpires, true
				if !c.Quiet {
					log.Printf("  ⚖ policy: expiry capped to %s", humanDur(pol.maxExpires))
				}
			}
		}
	}

	s := &share{cfg: c, shutdown: make(chan string, 1), createdAt: time.Now()}

	// identity (needed before stdin buffering names its temp file)
	s.id = c.daemonID
	if s.id == "" {
		s.id = randToken(6)
	}
	if c.Name != "" {
		s.token = c.Name
	} else {
		s.token = randToken(c.TokenLen)
	}

	// resolve targets
	oneInput := !c.Upload && !c.Blackhole && !c.Room && !c.Call && !c.Hub && !c.Kuma && !c.Dashboard && len(c.RunCmd) == 0 && len(c.Paths) == 1
	// -s, or a localhost URL ("automatically if it is not a website"), means
	// reverse-proxy a running server rather than download it.
	serverMode := oneInput && looksLikeURL(c.Paths[0]) && (c.Server || isLocalServerURL(c.Paths[0]))
	fetchMode := oneInput && c.Fetch && !serverMode && looksLikeURL(c.Paths[0])
	ytMode := oneInput && !c.Fetch && !serverMode && (c.YtDlp || looksLikeURL(c.Paths[0]))
	switch {
	case len(c.RunCmd) > 0:
		if err := setupRun(c, s); err != nil {
			return err
		}
	case serverMode:
		if err := setupServer(c, s); err != nil {
			return err
		}
	case c.Site:
		root, index, err := resolveSite(c.Paths)
		if err != nil {
			return err
		}
		s.mode = "site"
		s.siteIndex = index
		s.roots = []rootEnt{{Name: filepath.Base(root), Abs: root, IsDir: true}}
		if c.AllowUpload { // --site --allow-upload: pages run as a site AND __upload works (e.g. GIGA-NET/1-L game signalling)
			s.upDir = root
		}
		if c.GameLink {
			if c.gameSidSeed != "" { // daemon child / resumed persist: keep the id already handed out
				s.gameSid = c.gameSidSeed
			} else {
				s.gameSid = randSid(8)
			}
		}
		if !c.Quiet {
			fmt.Fprintf(os.Stderr, "  🌐 serving site root %s (index: %s)\n", root, index)
		}
	case c.Progress && oneInput:
		if c.Background {
			return errors.New("--progressive/--live can't run in the background (-b)")
		}
		if err := setupProgressive(c, s); err != nil {
			return err
		}
	case fetchMode:
		roots, file, err := fetchURL(c, s.id)
		if err != nil {
			if file != "" {
				os.Remove(file)
			}
			return err
		}
		s.mode = "file"
		s.srcArg = c.Paths[0]
		s.tmpRoot = file
		s.tmpFile = file
		s.roots = roots
	case ytMode && c.Playlist:
		// Playlists become a multi-file folder share; a listing only makes sense
		// once the files exist, so keep the blocking fetch.
		roots, dir, err := ytFetch(c, s.id)
		if err != nil {
			if dir != "" {
				os.RemoveAll(dir)
			}
			return err
		}
		s.srcArg = c.Paths[0]
		s.tmpDir = dir
		s.roots = roots
		if len(roots) == 1 && !roots[0].IsDir {
			s.mode = "file"
			s.tmpRoot = roots[0].Abs
		} else {
			s.mode = "dir"
			s.tmpRoot = dir
			s.roots = []rootEnt{{Name: filepath.Base(dir), Abs: dir, IsDir: true}}
		}
	case ytMode:
		// Single-file download: bring the share online immediately (link + QR),
		// then download in the background. Resolve the eventual filename first so
		// the printed link is real and visitors can be held with a percentage
		// page until the file is ready.
		dir, err := ytMakeDir(s.id)
		if err != nil {
			return err
		}
		name, err := ytFilename(c, dir)
		if err != nil {
			os.RemoveAll(dir)
			return err
		}
		s.mode = "file"
		s.srcArg = c.Paths[0]
		s.tmpDir = dir
		s.tmpRoot = filepath.Join(dir, name)
		s.roots = []rootEnt{{Name: name, Abs: filepath.Join(dir, name)}}
		s.ytPend = &ytPending{}
		s.afterAnnounce = func() { go ytDownload(c, s) }
	case len(c.Paths) == 1 && c.Paths[0] == "-" && !c.Upload:
		p, name, err := bufferStdin(c, s.id)
		if err != nil {
			return err
		}
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		if fi.Size() == 0 {
			os.Remove(p)
			return errors.New("stdin was empty — nothing to share")
		}
		fmt.Fprintf(os.Stderr, "  ⇣ buffered %s from stdin\n", humanSize(fi.Size()))
		s.mode = "file"
		s.srcArg = "-"
		s.tmpRoot = p
		s.tmpFile = p
		s.roots = []rootEnt{{Name: name, Abs: p, IsDir: false, Size: fi.Size()}}
	case c.Hub:
		// --hub: a homescreen-style 2-way remote. One folder is both an inbox
		// (upload from any phone) and a drop target for web grabs (paste a URL,
		// the host fetches it), plus a browsable/deletable file list. Add-to-
		// Home-Screen turns the token link into an app-like control panel.
		dir := "tshare-hub"
		if len(c.Paths) == 1 {
			dir = c.Paths[0]
		} else if len(c.Paths) > 1 {
			return errors.New("--hub takes at most one directory")
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(abs, 0o755); err != nil {
			return err
		}
		s.mode, s.upDir = "hub", abs
		s.jobs = newJobHub(abs)
		s.roots = []rootEnt{{Name: filepath.Base(abs), Abs: abs, IsDir: true}}
	case c.Call:
		// --call: the secret link IS a 1:1 WebRTC video call. tshare hosts the
		// page + signaling; media flows peer-to-peer. No MiroTalk needed.
		if len(c.Paths) > 0 {
			return errors.New("--call takes no path — the link itself is the call")
		}
		s.mode = "call"
		s.hub = newRTCHub()
		s.roots = []rootEnt{{Name: "call", Abs: "webrtc-call", IsDir: false}}
	case c.Dashboard:
		// --dashboard: a pathless webui listing every OTHER active share as an
		// iOS-home-screen tile grid. Password-gated (auto-minted if none given).
		if len(c.Paths) > 0 {
			return errors.New("--dashboard takes no path — it lists your active shares")
		}
		if c.Password == "" {
			c.Password = randToken(4) // ~8 hex chars
			if !c.Quiet {
				fmt.Fprintf(os.Stderr, "  🔑 dashboard password: %s   (username: anything)\n", c.Password)
			}
		}
		s.mode = "dashboard"
		s.roots = []rootEnt{{Name: "dashboard", Abs: "dashboard", IsDir: false}}
	case c.Kuma:
		// --kuma: expose Uptime Kuma at the funnel root (it can't run under a
		// subpath). Reuse a running instance or start the native install on demand;
		// resolved later so we have the funnel host for the dashboard URL.
		if len(c.Paths) > 0 {
			return errors.New("--kuma takes no path — it exposes your Uptime Kuma dashboard")
		}
		if err := kumaApp.preflight(c); err != nil { // fail before mounting anything
			return err
		}
		s.mode, s.kuma = "kuma", true
		s.roots = []rootEnt{{Name: "uptime-kuma", Abs: "uptime-kuma", IsDir: false}}
	case c.Room:
		// --room: no file at all — serve a token-gated landing page that opens a
		// MiroTalk video room. The secret link (and any -p/-e) gate who reaches the
		// join button; the call itself runs on the MiroTalk instance. With no
		// --mirotalk-url the LOCAL install is used (started on demand and exposed
		// at the funnel ROOT path — MiroTalk needs root, it breaks under /<token>/).
		name := c.RoomName
		if name == "" && len(c.Paths) == 1 {
			name = c.Paths[0]
		} else if len(c.Paths) > 1 {
			return errors.New("--room takes at most one room name")
		}
		if name == "" {
			name = "tshare-" + randToken(5) // unguessable room id
		}
		name = sanitizeRoomName(name)
		if name == "" {
			return errors.New("--room name may contain only letters, digits, dash, underscore")
		}
		s.mode = "room"
		s.roomName = name
		base := strings.TrimRight(c.MirotalkURL, "/")
		switch {
		case base != "":
			if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
				return errors.New("--mirotalk-url must be an http(s) URL")
			}
			s.roomURL = base + "/join?room=" + url.QueryEscape(name)
		default:
			// local instance: resolved/started later (needs the funnel host for the
			// join URL). Verify it's locatable now so the error comes before mounting.
			if err := mirotalkApp.preflight(c); err != nil {
				return err
			}
			s.roomLocal = true
		}
		s.roots = []rootEnt{{Name: name, Abs: "mirotalk:" + name, IsDir: false}}
	case c.Blackhole:
		// -i: a write-only sink. Uploads are read, counted and notified, but the
		// bytes are streamed to io.Discard — nothing ever touches disk. upDir is a
		// sentinel so handleUpload accepts POSTs; blackhole=true makes it discard.
		if len(c.Paths) > 0 {
			return errors.New("-i (blackhole) takes no path — bytes are discarded; use -u <dir> to keep uploads")
		}
		if c.Encrypt {
			return errors.New("-i (blackhole) discards uploads; --encrypt has nothing to write")
		}
		s.mode, s.upDir = "inbox", "\x00blackhole" // sentinel; blackhole wired below
		s.roots = []rootEnt{{Name: "blackhole", Abs: "", IsDir: true}}
	case c.Upload:
		dir := "tshare-inbox"
		if len(c.Paths) == 1 {
			dir = c.Paths[0]
		} else if len(c.Paths) > 1 {
			return errors.New("inbox mode takes at most one directory")
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(abs, 0o755); err != nil {
			return err
		}
		s.mode, s.upDir = "inbox", abs
		s.roots = []rootEnt{{Name: filepath.Base(abs), Abs: abs, IsDir: true}}
	case len(c.Paths) == 0:
		fmt.Print(usageText)
		return errors.New("nothing to share")
	default:
		seen := map[string]bool{}
		for _, p := range c.Paths {
			if p == "-" {
				return errors.New("stdin (-) must be the only path")
			}
			abs, err := filepath.Abs(p)
			if err != nil {
				return err
			}
			abs, err = filepath.EvalSymlinks(abs)
			if err != nil {
				return fmt.Errorf("%s: %w", p, err)
			}
			fi, err := os.Stat(abs)
			if err != nil {
				return err
			}
			name := filepath.Base(abs)
			if seen[name] {
				return fmt.Errorf("duplicate name %q — share conflicting paths separately", name)
			}
			seen[name] = true
			s.roots = append(s.roots, rootEnt{Name: name, Abs: abs, IsDir: fi.IsDir(), Size: fi.Size()})
		}
		if len(s.roots) == 1 {
			if s.roots[0].IsDir {
				s.mode = "dir"
				if c.AllowUpload {
					s.upDir = s.roots[0].Abs
				}
			} else {
				s.mode = "file"
				if c.AllowUpload {
					return errors.New("--allow-upload needs a folder share")
				}
			}
		} else {
			s.mode = "multi"
			if c.AllowUpload {
				return errors.New("--allow-upload works with a single folder share")
			}
		}
	}
	if c.Zip && s.mode == "file" {
		c.Zip = false // zipping one file is pointless; serve as-is
	}
	// --rar: split the payload into RAR volumes and share the volume folder
	// instead — transfer chunking, not compression (-m0). The default 1400M
	// volume fits an iPhone's ~1.5 GB in-memory P2P receive, so a huge file
	// becomes parts a phone can actually take. Needs `rar` on PATH.
	if c.Rar {
		if s.mode != "file" && s.mode != "dir" || s.grow != nil || s.ytPend != nil {
			return errors.New("--rar works with a local file or folder share (fully downloaded)")
		}
		if s.tmpDir != "" {
			return errors.New("--rar doesn't combine with shares that already stage a temp folder (e.g. --playlist)")
		}
		if _, err := exec.LookPath("rar"); err != nil { // fail fast even in the daemonizing parent
			return errors.New("rar not found — install it first (brew install rar) to use --rar")
		}
		// Only the process that actually serves splits. Under -b the daemonizing
		// parent skips it (the re-exec'd child does the real split with the same
		// id → same dir), so a big file isn't split twice.
		if !c.Background || c.daemonChild {
			dir, err := rarSplit(c, s.roots[0], s.id)
			if err != nil {
				return err
			}
			s.mode = "dir"
			s.tmpDir = dir // volumes are temporary — removed when the share stops
			s.upDir = ""
			s.roots = []rootEnt{{Name: s.roots[0].Name + " (rar volumes)", Abs: dir, IsDir: true}}
		}
	}
	// --p2p: enable the direct WebRTC transfer path. A local browser tab is
	// the sender, so it needs a foreground share. Folder shares get a per-file
	// transfer list (each RAR volume rides its own DataChannel).
	if c.P2P {
		if s.mode != "file" && s.mode != "dir" {
			return errors.New("--p2p works with a single file or a folder share (e.g. --rar volumes)")
		}
		if c.Background {
			return errors.New("--p2p needs a foreground share — a local sender tab must stay open (-b won't have one)")
		}
		s.senderKey = randToken(16)
		s.hub = newRTCHub()
	}
	// --filename also renames any single-file share's public name
	if c.FileName != "" && s.mode == "file" {
		if n := sanitizeName(c.FileName); n != "" {
			s.roots[0].Name = n
		}
	}
	// discoverability: a plain .html / a folder with an index downloads or shows
	// a file browser — nudge toward --site, which renders it as a live website.
	if !c.Site && !c.daemonChild && !c.Quiet {
		if s.mode == "file" {
			if e := strings.ToLower(filepath.Ext(s.roots[0].Name)); e == ".html" || e == ".htm" {
				log.Printf("  ℹ serving this .html as a web page (scripts run) · add ?dl=1 to the link to download it instead")
			}
		} else if s.mode == "dir" && fileExists(filepath.Join(s.roots[0].Abs, "index.html")) {
			log.Printf("  ℹ folder has index.html — add --site to serve it as a live website")
		}
	}

	var err error
	s.maxUp, err = parseSize(c.MaxUpload)
	if err != nil {
		return err
	}
	if s.maxUp == 0 {
		s.maxUp = 5 << 30
	}
	// #13: byte cap. Once served bytes reach the cap, new transfers are
	// refused; in-flight ones may run on up to a 1.5× hard ceiling, then stop.
	if s.maxBytes, err = parseSize(c.MaxBytes); err != nil {
		return err
	}

	// bandwidth throttle: a single per-share token bucket shared across all
	// connections, so `--max-rate 2M` caps total served throughput at ~2 MB/s.
	if rate, err := parseSize(c.MaxRate); err != nil {
		return err
	} else if rate > 0 {
		s.limiter = newRateLimiter(rate)
	}

	// disk guardrail: refuse uploads once free space drops below this. Only
	// meaningful for shares that accept writes; 0 disables it.
	if s.minFree, err = parseSize(c.MinFree); err != nil {
		return err
	}
	s.blackhole = c.Blackhole

	// #10: at-rest encryption key for received files. Reuse the bg-inherited
	// key, else derive from the password, else generate and print one once.
	if c.Encrypt || c.encKeyHex != "" {
		if s.encKey, err = resolveEncKey(c); err != nil {
			return err
		}
	}

	// runtime-mutable settings (changeable later via `tshare set`)
	s.password = c.Password
	s.maxDL.Store(c.MaxDL)
	if c.Expires > 0 {
		s.expiresAt = time.Now().Add(c.Expires)
	}

	// background: re-exec a detached child, wait for it to publish its state
	if c.Background && !c.daemonChild {
		return daemonize(s)
	}

	// listener — bind all interfaces when we also want direct LAN reach
	// (always in --local; otherwise unless --no-lan). tailscaled still proxies
	// funnel/serve traffic via loopback, so this only ADDS a LAN path.
	lanOn := c.Local || (c.LAN && !c.NoLAN)
	bind := "127.0.0.1:"
	if lanOn {
		bind = "0.0.0.0:"
	}
	ln, err := net.Listen("tcp", bind+strconv.Itoa(c.Port))
	if err != nil {
		return err
	}
	port := ln.Addr().(*net.TCPAddr).Port

	// #64: self-signed TLS for LAN-only HTTPS (only meaningful in --local;
	// funnel/serve needs a plain-HTTP loopback backend for tailscaled).
	scheme := "http"
	if c.LanHTTPS {
		if !c.Local {
			return errors.New("--lan-https only applies with --local (Tailscale already provides HTTPS)")
		}
		tc, err := selfSignedTLS([]string{lanIP(), "127.0.0.1", "localhost"})
		if err != nil {
			return err
		}
		ln = tls.NewListener(ln, tc)
		scheme = "https"
	}

	// public/tailnet URL + tailscale registration
	if c.Local {
		s.baseURL = fmt.Sprintf("%s://%s:%d/%s", scheme, lanIP(), port, s.token)
	} else {
		ts, err := tsStatus(c)
		if err != nil {
			return fmt.Errorf("tailscale not ready: %v\n  (try: tshare doctor, or --local for LAN-only)", err)
		}
		host := strings.TrimSuffix(ts.Self.DNSName, ".")
		if host == "" {
			return errors.New("no MagicDNS name; enable MagicDNS + HTTPS in the Tailscale admin console")
		}
		if nameInUse(s.token) {
			return fmt.Errorf("path /%s is already used by another tshare share", s.token)
		}
		if out, err := tsMount(c, s.token, port); err != nil {
			// #68: Funnel not available (attribute off, etc.) — automatically
			// fall back to tailnet-only serve so the share still works, unless
			// the user explicitly asked for funnel-only behavior.
			if !c.Tailnet && funnelUnavailable(out) {
				if out2, err2 := tsMount(&config{Tailnet: true, HTTPSPort: c.HTTPSPort, TSBin: c.TSBin}, s.token, port); err2 == nil {
					c.Tailnet = true
					fmt.Fprintln(os.Stderr, "  ⚠ Funnel unavailable — fell back to tailnet-only (serve).")
					fmt.Fprintln(os.Stderr, "    enable Funnel for public links: https://tailscale.com/kb/1223/funnel")
				} else {
					return fmt.Errorf("tailscale funnel failed:\n%s\n  and serve fallback failed:\n%s", strings.TrimSpace(out), strings.TrimSpace(out2))
				}
			} else {
				return fmt.Errorf("tailscale %s failed:\n%s\n  hint: run `tshare doctor` (Funnel needs the funnel node attribute and HTTPS certs: https://tailscale.com/kb/1223/funnel)", verb(c), strings.TrimSpace(out))
			}
		}
		if c.HTTPSPort == 443 {
			s.baseURL = fmt.Sprintf("https://%s/%s", host, s.token)
		} else {
			s.baseURL = fmt.Sprintf("https://%s:%d/%s", host, c.HTTPSPort, s.token)
		}
		// Warn if this "public" funnel link won't actually resolve on the public
		// internet (Tailscale hasn't published the *.ts.net DNS record) — else the
		// user hands out a link that only works inside their tailnet. Async so it
		// never delays the share coming up; the tip points at doctor for the fix.
		if !c.Tailnet && !c.Quiet {
			go func(h string) {
				if !resolvesPublicly(h) {
					fmt.Fprintf(os.Stderr, "  ⚠ %s has no PUBLIC DNS record — this link works on your tailnet\n", h)
					fmt.Fprintln(os.Stderr, "     but NOT the public internet (Funnel DNS isn't published). Fix:")
					fmt.Fprintln(os.Stderr, "       tailscale funnel reset && tailscale up   (then re-run · see: tshare doctor)")
					fmt.Fprintln(os.Stderr, "     …or use -t for an intentionally tailnet-only link.")
				}
			}(host)
		}
		// extra direct-LAN URL (plain HTTP, token required for direct hits)
		if lanOn {
			if ip := lanIP(); ip != "127.0.0.1" {
				s.lanURL = fmt.Sprintf("http://%s:%d/%s", ip, port, s.token)
			}
		}
	}

	// state file
	if err := s.saveState(port); err != nil {
		log.Printf("warn: %v", err)
	}
	cleanup := func() {
		if !c.Local {
			tsUnmount(c, s.token)
		}
		os.Remove(stateFile(s.id))
		if s.ctlPath != "" {
			os.Remove(s.ctlPath)
		}
		if s.tmpFile != "" {
			os.Remove(s.tmpFile)
		}
		if s.tmpDir != "" {
			os.RemoveAll(s.tmpDir)
		}
		if c.daemonTmp != "" {
			os.Remove(c.daemonTmp)
		}
		if c.daemonTmpDir != "" {
			os.RemoveAll(c.daemonTmpDir)
		}
		// intentional stop/expiry → drop the resume record (reboot keeps it,
		// because cleanup doesn't run when the process is killed by shutdown)
		os.Remove(persistFile(s.id))
		if s.cpCmd != nil && s.cpCmd.Process != nil {
			s.cpCmd.Process.Kill()
		}
		if s.mtRootMounted {
			tsUnmount(c, "") // root path we mounted for local MiroTalk
		}
		for _, p := range s.procs { // stop every managed server (run/host/room)
			p.stop()
		}
	}
	defer cleanup()

	// --room with the LOCAL MiroTalk: start it (or reuse a running one), expose
	// it at the funnel/serve ROOT path, and point the join URL at that origin.
	// Runs after `defer cleanup()` so a failure can't leak the child process.
	if s.roomLocal {
		if err := mirotalkApp.start(s); err != nil {
			return err
		}
		if c.Local {
			// same-machine testing only: cam/mic need a secure context, so plain
			// LAN HTTP works from this machine (localhost) but not from others.
			origin := fmt.Sprintf("http://%s:%d", lanIP(), c.MirotalkPort)
			s.roomURL = origin + "/join?room=" + url.QueryEscape(s.roomName)
			if !c.Quiet {
				log.Printf("  ⚠ --local room: browsers block cam/mic on plain HTTP except on this machine — use funnel/serve for real calls")
			}
		} else {
			if out, err := tsMount(c, "", c.MirotalkPort); err != nil {
				return fmt.Errorf("mounting MiroTalk at the %s root failed:\n%s", verb(c), strings.TrimSpace(out))
			}
			s.mtRootMounted = true
			u, err := url.Parse(s.baseURL)
			if err != nil {
				return err
			}
			s.roomURL = u.Scheme + "://" + u.Host + "/join?room=" + url.QueryEscape(s.roomName)
		}
		s.roots[0].Abs = s.roomURL
		s.updateState() // re-record: join URL + child pid + root mount now exist
	}

	// --kuma: make sure Uptime Kuma is up (reuse a running one or start the
	// native install — auto-stopped with the share), then mount it at the
	// funnel/serve ROOT and point the dashboard URL there.
	if s.kuma {
		if err := kumaApp.start(s); err != nil {
			return err
		}
		if c.Local { // LAN-only: reach Kuma directly, no funnel root mount
			s.kumaURL = fmt.Sprintf("http://%s:%d/", lanIP(), c.KumaPort)
		} else {
			if out, err := tsMount(c, "", c.KumaPort); err != nil {
				return fmt.Errorf("mounting Uptime Kuma at the %s root failed:\n%s", verb(c), strings.TrimSpace(out))
			}
			s.mtRootMounted = true
			if u, err := url.Parse(s.baseURL); err == nil {
				s.kumaURL = u.Scheme + "://" + u.Host + "/"
			}
		}
		s.roots[0].Abs = s.kumaURL
		s.updateState()
	}

	// copyparty folder engine: for single-folder browse/upload shares, hand the
	// heavy lifting (resumable uploads, dedup, thumbnails, WebDAV) to copyparty
	// on loopback and reverse-proxy to it — tshare keeps the token gate,
	// password, expiry, byte cap, logging and probe alerts in front.
	if s.useCopyparty() {
		if err := startCopyparty(s); err != nil {
			if c.Copyparty { // explicitly requested → hard error
				return err
			}
			if !c.Quiet {
				log.Printf("  copyparty failed to start — using native folder server:\n  %v", err)
			}
		} else if !c.Quiet {
			log.Printf("  ▷ folders served by copyparty (pid %d) behind tshare", s.cpCmd.Process.Pid)
		}
	} else if (s.mode == "dir" || s.mode == "inbox") && !c.NoCopyparty && s.encKey == nil && !c.Quiet {
		// folder share, auto mode, copyparty simply not detected — say so, since
		// otherwise the native fallback is silent and looks like nothing happened.
		log.Printf("  ℹ using built-in folder server (copyparty not found).")
		log.Printf("     for resumable uploads/thumbnails: pip install copyparty   (check: tshare doctor)")
	}

	// control socket for `tshare set` / `tshare info`
	s.ctlServe()

	// announce
	s.announce(port)

	// --gamelink: open this machine's browser straight into host mode — the page
	// creates the WebRTC offer itself (#gnhost), so hosting needs zero clicks.
	if s.gameSid != "" && !c.daemonChild {
		_, hostURL := s.gameLinks()
		if c.NoOpen {
			fmt.Fprintf(os.Stderr, "  🎮 open this on the host machine: %s\n", hostURL)
		} else {
			fmt.Fprintf(os.Stderr, "  🎮 host page opened — send the join link (already on your clipboard)\n")
			openBrowser(hostURL)
		}
	}

	// --p2p: open the local sender tab (it streams the file into DataChannels).
	if s.senderKey != "" {
		sendURL := fmt.Sprintf("http://127.0.0.1:%d/%s/__p2p/send?k=%s", port, s.token, s.senderKey)
		if c.NoOpen {
			fmt.Fprintf(os.Stderr, "  ⚡ p2p sender page (open it and keep the tab up): %s\n", sendURL)
		} else {
			fmt.Fprintf(os.Stderr, "  ⚡ p2p sender tab opened — keep it open (re-open: %s)\n", sendURL)
			openBrowser(sendURL)
		}
	}

	// start any deferred work that should run only after the link/QR is printed
	// (e.g. the background yt-dlp download for a single-file share)
	if s.afterAnnounce != nil {
		s.afterAnnounce()
	}

	// serve
	started := time.Now()
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second, // keep-alive reuse; reaps idle conns
		// (no WriteTimeout: it would abort long downloads/streams)
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()

	// expiry watcher (polling, so `tshare set -e` changes apply live) + a
	// coalesced flusher for the throttled state file (keeps disk I/O off the
	// download hot path while still landing within a couple seconds).
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for range t.C {
			s.stateMu.Lock()
			s.flushStateLocked()
			s.stateMu.Unlock()
			if s.expired() {
				s.trigger("expired")
				return
			}
		}
	}()

	// #84: record for `tshare resume` after a reboot
	if c.Persist {
		if err := savePersist(s); err != nil && !c.Quiet {
			log.Printf("warn: could not persist for resume: %v", err)
		}
	}
	// #74: watch a shared folder and announce new files as they appear
	if c.Watch && (s.mode == "dir" || s.mode == "multi" || s.mode == "inbox") {
		go s.watchDir()
	}
	// interactive: type options into the running share to change them live
	if !c.daemonChild && !c.NoREPL && s.grow == nil && isatty(os.Stdin) && !c.Quiet {
		go s.repl()
	}

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	var reason string
	select {
	case sg := <-sig:
		reason = sg.String()
	case reason = <-s.shutdown:
	case err := <-errCh:
		return err // deferred cleanup runs
	}
	if !c.Quiet {
		log.Printf("⏹  stopping (%s)…", reason)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	if !c.Quiet {
		log.Printf("  done · %d download(s) · %d upload(s) · up %s",
			s.dl.Load(), s.upCount.Load(), time.Since(started).Round(time.Second))
	}
	return nil
}

func (s *share) trigger(reason string) {
	select {
	case s.shutdown <- reason:
	default:
	}
}

func verb(c *config) string {
	if c.Tailnet {
		return "serve"
	}
	return "funnel"
}

func validSlug(s string) bool {
	if len(s) == 0 || len(s) > 64 || strings.HasPrefix(s, "__") {
		return false
	}
	for _, r := range s {
		ok := r == '.' || r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

// sanitizeRoomName keeps a MiroTalk room id URL-safe: spaces → dashes, then only
// letters/digits/dash/underscore/dot survive. "" if nothing usable is left.
func sanitizeRoomName(n string) string {
	n = strings.TrimSpace(n)
	var b strings.Builder
	for _, r := range n {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case r == '.' || r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func randToken(n int) string {
	const cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = cs[b[i]&63]
	}
	return string(b)
}

// randSid mints a GIGA-NET/1-L session id — lowercase alphanumeric only, since
// that's the charset the game pages accept in #gn=/#gnhost= fragments. A
// 32-char set indexed with &31 keeps the draw uniform (no modulo bias); the
// share token remains the actual access gate, the sid just names the session.
func randSid(n int) string {
	const cs = "0123456789abcdefghijklmnopqrstuv" // 32 chars ⊂ [a-z0-9]
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = cs[b[i]&31]
	}
	return string(b)
}

func (s *share) announce(port int) {
	c := s.cfg
	link := s.prettyURL()
	gameJoin, gameHost := s.gameLinks()
	if c.JSON {
		meta := map[string]any{
			"id": s.id, "url": link, "base": s.baseURL + "/", "mode": s.mode,
			"token": s.token, "port": port, "password": c.Password != "",
			"tailnet_only": c.Tailnet, "local": c.Local,
			"max_downloads": c.MaxDL, "pid": os.Getpid(),
		}
		if gameJoin != "" {
			meta["game_join"] = gameJoin
			meta["game_host"] = gameHost
		}
		if t := s.getExpires(); !t.IsZero() {
			meta["expires_at"] = t.Format(time.RFC3339)
		}
		j, _ := json.MarshalIndent(meta, "", "  ")
		fmt.Println(string(j))
	} else if c.Quiet {
		if gameJoin != "" { // the join link is the artifact you want to pipe/send
			fmt.Println(gameJoin)
		} else {
			fmt.Println(link)
		}
	} else {
		scope := "public + tailnet (funnel)"
		if c.Tailnet {
			scope = "tailnet only (serve)"
		}
		if c.Local {
			scope = "local network only"
		}
		exp := "never"
		if t := s.getExpires(); !t.IsZero() {
			exp = fmt.Sprintf("%s (in %s)", t.Format("Jan 2 15:04"), humanDur(time.Until(t)))
		}
		max := "∞"
		if c.MaxDL > 0 {
			max = strconv.FormatInt(c.MaxDL, 10)
		}
		pw := "none"
		if c.Password != "" {
			pw = "required"
		}
		what := s.describe()
		fmt.Printf("\n  tshare v%s · %s\n\n", version, s.mode)
		fmt.Printf("  sharing    %s\n", what)
		if s.mode == "file" && isMedia(s.roots[0].Name) && !s.cfg.Inline {
			fmt.Printf("  view       %s\n", link)
			fmt.Printf("  download   %s?dl=1\n", link)
		} else {
			fmt.Printf("  link       %s\n", link)
		}
		if s.lanURL != "" {
			fmt.Printf("  lan        %s   (same network, faster, no internet)\n", s.lanLink())
		}
		if gameJoin != "" {
			fmt.Printf("  🎮 join    %s   ← send THIS to the other player\n", gameJoin)
			fmt.Printf("  🎮 host    %s   (opens here automatically)\n", gameHost)
		}
		fmt.Printf("  curl       %s\n", s.curlHint())
		fmt.Printf("  scope      %-28s id        %s\n", scope, s.id)
		fmt.Printf("  password   %-28s expires   %s\n", pw, exp)
		fmt.Printf("  max-dl     %-28s port      %d\n", max, port)
		if c.Background && c.daemonChild {
			fmt.Printf("\n  stop with: tshare rm %s\n", s.id)
		} else {
			fmt.Printf("\n  Ctrl-C to stop · tshare ls · change live: tshare set %s -p pw -e 2d\n", s.id)
		}
		fmt.Println()
	}
	if !c.daemonChild { // daemon child logs to a file; parent handles extras
		if gameJoin != "" {
			linkExtras(c, gameJoin) // for a game share, the JOIN link is what gets copied/QR'd
		} else {
			linkExtras(c, link)
		}
	}
}

// linkExtras: clipboard, QR, browser — defaults on, individually disableable.
func linkExtras(c *config, link string) {
	if c.Copy && !c.NoCopy {
		if copyClipboard(link) {
			fmt.Fprintln(os.Stderr, "  ✓ link copied to clipboard")
		} else if !c.Quiet && !c.JSON {
			fmt.Fprintln(os.Stderr, "  (clipboard unavailable — need pbcopy / wl-copy / xclip)")
		}
	}
	if !c.NoQR && (c.QR || (!c.Quiet && !c.JSON)) {
		if qrencodeOK() {
			printQR(link)
		} else if c.QR || (!c.Quiet && !c.JSON) {
			fmt.Fprintln(os.Stderr, "  (tip: install qrencode for a scannable QR — brew install qrencode)")
		}
	}
	if c.Open {
		openBrowser(link)
	}
}

func (s *share) describe() string {
	cp := ""
	if s.cpProxy != nil {
		cp = " · copyparty"
	}
	switch s.mode {
	case "file":
		if s.ytPend != nil {
			if _, done, _ := s.ytPend.state(); !done {
				return fmt.Sprintf("%s (downloading…)", s.roots[0].Name)
			}
		}
		return fmt.Sprintf("%s (%s)", s.roots[0].Abs, humanSize(s.roots[0].Size))
	case "server":
		return "reverse proxy → " + s.srvURL
	case "site":
		return fmt.Sprintf("website %s (index: %s)", s.roots[0].Abs, s.siteIndex)
	case "room":
		return "video room → " + s.roomURL
	case "kuma":
		return "Uptime Kuma → " + s.kumaURL
	case "dashboard":
		return "dashboard (all active shares)"
	case "call":
		return "video call (built-in 1:1, WebRTC P2P)"
	case "hub":
		return fmt.Sprintf("hub (2-way remote) → %s", s.upDir)
	case "inbox":
		return fmt.Sprintf("inbox → %s%s", s.upDir, cp)
	case "multi":
		return fmt.Sprintf("%d items", len(s.roots))
	default:
		extra := ""
		if s.cfg.Zip {
			extra = " (as zip)"
		}
		if s.upDir != "" {
			extra = " (uploads allowed)"
		}
		return s.roots[0].Abs + extra + cp
	}
}

func (s *share) prettyURL() string {
	if s.mode == "file" {
		return s.baseURL + "/" + url.PathEscape(s.roots[0].Name)
	}
	return s.baseURL + "/"
}

// gameLinks returns the GIGA-NET/1-L join/host URLs for a --gamelink share.
// The game page is the site's default document, so the bare share URL renders
// it; the fragment stays client-side and never appears in any server log.
func (s *share) gameLinks() (join, host string) {
	if s.gameSid == "" {
		return "", ""
	}
	base := s.prettyURL()
	return base + "#gn=" + s.gameSid, base + "#gnhost=" + s.gameSid
}

// lanLink is the direct-LAN equivalent of prettyURL (plain HTTP, token in path).
func (s *share) lanLink() string {
	if s.lanURL == "" {
		return ""
	}
	if s.mode == "file" {
		return s.lanURL + "/" + url.PathEscape(s.roots[0].Name)
	}
	return s.lanURL + "/"
}

func (s *share) curlHint() string {
	auth := ""
	if s.cfg.Password != "" {
		auth = "-u :<password> "
	}
	switch s.mode {
	case "file":
		return "curl " + auth + "-OJ \"" + s.prettyURL() + "?dl=1\""
	case "server":
		return "open " + s.baseURL + "/   (proxies " + s.srvURL + ")"
	case "site":
		return "open " + s.baseURL + "/   (live website)"
	case "room":
		return "open " + s.baseURL + "/   (video room: " + s.roomName + ")"
	case "kuma":
		return "open " + s.baseURL + "/   (Uptime Kuma dashboard)"
	case "dashboard":
		return "open " + s.baseURL + "/   (your shares — home screen)"
	case "call":
		return "open " + s.baseURL + "/   (send this link to ONE other person)"
	case "hub":
		return "open " + s.baseURL + "/   (upload · grab URLs · browse — Add to Home Screen)"
	case "inbox":
		return "curl " + auth + "-F f=@file.txt " + s.baseURL + "/__upload"
	default:
		return "curl " + auth + "-o all.zip " + s.baseURL + "/__zip"
	}
}

// ---------------------------------------------------------------------------
// #74 watch a shared folder and announce new files

func (s *share) watchRoot() string {
	if s.blackhole { // no real directory to watch
		return ""
	}
	if s.mode == "inbox" {
		return s.upDir
	}
	if len(s.roots) == 1 && s.roots[0].IsDir {
		return s.roots[0].Abs
	}
	return ""
}

func (s *share) watchDir() {
	root := s.watchRoot()
	if root == "" {
		return
	}
	seen := map[string]bool{}
	if des, err := os.ReadDir(root); err == nil {
		for _, de := range des {
			seen[de.Name()] = true
		}
	}
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for range t.C {
		des, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, de := range des {
			n := de.Name()
			if seen[n] || strings.HasPrefix(n, ".") {
				continue
			}
			seen[n] = true
			if !s.cfg.Quiet {
				log.Printf("  ＋ new file in share: %s", n)
			}
			if !s.cfg.NoNotify {
				go notify("tshare", "new file shared: "+n)
			}
		}
	}
}
