//go:build unix

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// configuration

type config struct {
	Paths       []string
	Password    string
	Expires     time.Duration
	MaxDL       int64
	Once        bool
	TokenLen    int
	Name        string
	Tailnet     bool
	Upload      bool
	AllowUpload bool
	Zip         bool
	Site        bool // serve a folder as a live static website (index.html)
	GameLink    bool // --gamelink: --site --allow-upload + pre-minted GIGA-NET/1-L host/join links (one-command game hosting)
	Local       bool
	LAN         bool // also serve directly on the LAN (default on)
	NoLAN       bool // disable LAN serving (loopback only)
	Inline      bool
	Background  bool
	QR          bool
	Copy        bool
	NoQR        bool
	NoCopy      bool
	NoNotify    bool
	NoOpen      bool // suppress auto-opened pages (--p2p sender tab)
	Open        bool
	Quiet       bool
	JSON        bool
	ExpiresSet  bool
	MaxUpload   string
	HTTPSPort   int
	Port        int
	TSBin       string
	FileName    string

	// yt-dlp / fetching
	YtDlp    bool   // force treating the input as a yt-dlp URL
	YtFormat string // -f passthrough
	YtArgs   string // extra raw yt-dlp args (shell-split)
	YtAudio  bool   // extract audio → m4a/mp3 (smart)
	Playlist bool   // allow playlists (default: single video)
	Fetch    bool   // force plain HTTP fetch (wget-style) instead of yt-dlp
	Progress bool   // start serving while the download is still running
	Live     bool   // live stream: progressive + no length, ends at producer EOF
	Server   bool   // reverse-proxy an already-running local server (URL)

	// access & limits
	RequireID bool   // funnel: require an authenticated Tailscale identity
	MaxBytes  string // total bytes served before the link stops (e.g. 2G)
	MaxRate   string // per-share bandwidth cap for served bytes (e.g. 2M = 2 MB/s; "" = unlimited)
	MinFree   string // refuse uploads when free disk space drops below this (default 32G; 0 = off)

	// inbox / blackhole
	Blackhole bool // -i: accept + count uploads but discard the bytes (throughput sink)

	// video rooms (MiroTalk)
	Room           bool   // --room / --mirotalk: share a video-call room behind the secret link
	RoomName       string // explicit room id (else the positional arg, else random)
	MirotalkURL    string // remote instance base URL ("" = use/spawn the local install)
	MirotalkDir    string // local MiroTalk checkout (default ~/.tshare/mirotalk)
	MirotalkMethod string // how the local instance runs: npm | docker (auto-detected if "")
	MirotalkPort   int    // local MiroTalk port (default 7701)

	// hub (--hub): homescreen-style 2-way remote page — upload, grab URLs,
	// browse/manage the hub folder, from a phone or any browser
	Hub bool

	// --dashboard: an iOS-home-screen webui tiling every active share, on its
	// own password-gated link (a random password is minted if none is given).
	Dashboard bool

	// run/host (managed local server exposed over the funnel): launch a command
	// that serves on a port, auto-detect the port, reverse-proxy it. `tshare run`
	// and `tshare host <dir>` populate these; MiroTalk (--room) reuses the engine.
	RunCmd  []string // command + args to launch (empty = not a run share)
	RunDir  string   // working directory for the command
	RunName string   // display / tmux window name
	Tmux    bool     // --tmux: launch managed servers as windows of one 'tshare' tmux session

	// --kuma: reuse/start a persistent Uptime Kuma monitor and expose it at the
	// funnel root (Uptime Kuma can't run under a subpath). Native, auto start/stop.
	Kuma     bool
	KumaPort int    // default 7702
	KumaDir  string // local Uptime Kuma checkout (default ~/.tshare/kuma)

	// --rar: split the share into RAR volumes before serving (transfer
	// chunking — e.g. so each part fits an iPhone's in-memory P2P receive)
	Rar     bool
	RarSize string // volume size (default 1400M — under the 1.5 GB iOS cap)

	// browser WebRTC (P2P direct transfer + built-in call)
	P2P      bool   // --p2p: share also offers a direct DataChannel transfer
	Call     bool   // --call: built-in 1:1 WebRTC video call page (no MiroTalk needed)
	STUN     string // comma-separated STUN urls for ICE (NAT/CGNAT hole-punch)
	TURN     string // optional TURN url (guaranteed relay when hole-punch fails)
	TURNUser string // TURN credentials
	TURNPass string

	// abuse / legal
	AbuseContact string // small-font takedown/abuse contact shown on public share pages ("" = hidden)
	Legal        bool   // show a minimal copyright + DMCA-takedown line in the banner (opt-in)

	// media
	Transcode bool // pre-transcode incompatible video to MP4 (ffmpeg)
	Hevc      bool // transcode target is H.265/HEVC (hardware-accelerated)
	H265      bool // --265: hardware HEVC to a temp file at constant quality (CQ)
	CQ        int  // constant-quality value for --265 (default 50; lower = better/larger)
	Heif      bool // convert HEIC/HEIF images to JPEG for viewing
	StripExif bool // strip EXIF/metadata from served JPEGs
	NoGallery bool // disable the photo lightbox on image folders

	// at-rest encryption (inbox / uploads)
	Encrypt bool // encrypt received files at rest (AES-256-GCM)

	// copyparty (folder engine)
	Copyparty     bool   // force copyparty for folder shares
	NoCopyparty   bool   // never use copyparty (native folder server)
	CopypartyBin  string // explicit copyparty binary / sfx path
	CopypartyArgs string // extra raw copyparty args

	// ops
	LanHTTPS bool   // --local: serve HTTPS with a self-signed cert
	Profile  string // config profile name
	NoConf   bool   // skip reading the config file
	Watch    bool   // watch a directory and auto-share new files
	Persist  bool   // record share so `tshare resume` can restart it after reboot
	NoREPL   bool   // disable the interactive option prompt in the foreground

	// internal
	daemonChild  bool
	daemonID     string
	gameSidSeed  string // --__gamesid: reuse this GIGA-NET/1-L session id (daemon child / persist-resume) instead of minting a fresh one, so already-distributed join links keep working
	daemonTmp    string // temp file the daemon child must delete on exit
	daemonTmpDir string // temp dir the daemon child must delete on exit
	encKeyHex    string // passed to bg child so it inherits the inbox key
}

// defaultConfig is the base config (defaults) shared by the top-level share
// path and the run/host subcommands, so there's one source of truth.
func defaultConfig() *config {
	return &config{TokenLen: 16, HTTPSPort: 443, MaxUpload: "5G", MinFree: "32G", CQ: 50,
		RarSize:      "1400M",
		MirotalkPort: 7701, KumaPort: 7702,
		STUN: "stun:stun.l.google.com:19302,stun:stun.cloudflare.com:3478",
		Copy: true, LAN: true, Password: os.Getenv("TSHARE_PASSWORD")}
}

func registerFlags(fs *flag.FlagSet, c *config) {
	fs.StringVar(&c.Password, "p", c.Password, "")
	fs.StringVar(&c.Password, "password", c.Password, "")
	fs.Var(&durFlag{&c.Expires, &c.ExpiresSet}, "e", "")
	fs.Var(&durFlag{&c.Expires, &c.ExpiresSet}, "expires", "")
	fs.Int64Var(&c.MaxDL, "n", c.MaxDL, "")
	fs.Int64Var(&c.MaxDL, "max", c.MaxDL, "")
	fs.BoolVar(&c.Once, "once", c.Once, "")
	fs.IntVar(&c.TokenLen, "token-len", c.TokenLen, "")
	fs.StringVar(&c.Name, "name", c.Name, "")
	fs.BoolVar(&c.Tailnet, "t", c.Tailnet, "")
	fs.BoolVar(&c.Tailnet, "tailnet", c.Tailnet, "")
	fs.BoolVar(&c.Upload, "u", c.Upload, "")
	fs.BoolVar(&c.Upload, "upload", c.Upload, "")
	fs.BoolVar(&c.AllowUpload, "allow-upload", c.AllowUpload, "")
	fs.BoolVar(&c.Zip, "z", c.Zip, "")
	fs.BoolVar(&c.Zip, "zip", c.Zip, "")
	fs.BoolVar(&c.Site, "site", c.Site, "")
	fs.BoolVar(&c.Site, "web", c.Site, "")
	fs.BoolVar(&c.GameLink, "gamelink", c.GameLink, "")
	fs.BoolVar(&c.GameLink, "g", c.GameLink, "")
	fs.BoolVar(&c.Local, "l", c.Local, "")
	fs.BoolVar(&c.Local, "local", c.Local, "")
	fs.BoolVar(&c.LAN, "lan", c.LAN, "")
	fs.BoolVar(&c.NoLAN, "no-lan", c.NoLAN, "")
	fs.BoolVar(&c.Inline, "inline", c.Inline, "")
	fs.BoolVar(&c.Background, "b", c.Background, "")
	fs.BoolVar(&c.Background, "bg", c.Background, "")
	fs.BoolVar(&c.QR, "q", c.QR, "")
	fs.BoolVar(&c.QR, "qr", c.QR, "")
	fs.BoolVar(&c.Copy, "c", c.Copy, "")
	fs.BoolVar(&c.Copy, "copy", c.Copy, "")
	fs.BoolVar(&c.NoQR, "no-qr", c.NoQR, "")
	fs.BoolVar(&c.NoCopy, "no-copy", c.NoCopy, "")
	fs.BoolVar(&c.NoNotify, "no-notify", c.NoNotify, "")
	fs.BoolVar(&c.NoOpen, "no-open", c.NoOpen, "")
	fs.BoolVar(&c.Open, "open", c.Open, "")
	fs.BoolVar(&c.Quiet, "quiet", c.Quiet, "")
	fs.BoolVar(&c.JSON, "json", c.JSON, "")
	fs.StringVar(&c.MaxUpload, "max-upload", c.MaxUpload, "")
	fs.IntVar(&c.HTTPSPort, "https-port", c.HTTPSPort, "")
	fs.IntVar(&c.Port, "port", c.Port, "")
	fs.StringVar(&c.TSBin, "tailscale-bin", c.TSBin, "")
	fs.StringVar(&c.FileName, "filename", c.FileName, "")
	fs.BoolVar(&c.YtDlp, "Y", c.YtDlp, "")
	fs.BoolVar(&c.YtDlp, "yt-dlp", c.YtDlp, "")
	fs.StringVar(&c.YtFormat, "yt-format", c.YtFormat, "")
	fs.StringVar(&c.YtArgs, "yt-args", c.YtArgs, "")
	fs.BoolVar(&c.YtAudio, "a", c.YtAudio, "")
	fs.BoolVar(&c.YtAudio, "yt-audio", c.YtAudio, "")
	fs.BoolVar(&c.Playlist, "playlist", c.Playlist, "")
	fs.BoolVar(&c.Fetch, "fetch", c.Fetch, "")
	fs.BoolVar(&c.Progress, "progressive", c.Progress, "")
	fs.BoolVar(&c.Live, "live", c.Live, "")
	fs.BoolVar(&c.Server, "s", c.Server, "")
	fs.BoolVar(&c.Server, "server", c.Server, "")
	fs.BoolVar(&c.RequireID, "require-identity", c.RequireID, "")
	fs.StringVar(&c.MaxBytes, "max-bytes", c.MaxBytes, "")
	fs.StringVar(&c.MaxRate, "max-rate", c.MaxRate, "")
	fs.StringVar(&c.MinFree, "min-free", c.MinFree, "")
	fs.BoolVar(&c.Blackhole, "i", c.Blackhole, "")
	fs.BoolVar(&c.Blackhole, "blackhole", c.Blackhole, "")
	fs.BoolVar(&c.Room, "room", c.Room, "")
	fs.BoolVar(&c.Room, "mirotalk", c.Room, "")
	fs.StringVar(&c.RoomName, "room-name", c.RoomName, "")
	fs.StringVar(&c.MirotalkURL, "mirotalk-url", c.MirotalkURL, "")
	fs.StringVar(&c.MirotalkDir, "mirotalk-dir", c.MirotalkDir, "")
	fs.StringVar(&c.MirotalkMethod, "mirotalk-method", c.MirotalkMethod, "")
	fs.IntVar(&c.MirotalkPort, "mirotalk-port", c.MirotalkPort, "")
	fs.BoolVar(&c.P2P, "p2p", c.P2P, "")
	fs.BoolVar(&c.P2P, "p2pi", c.P2P, "") // common typo/alias
	fs.BoolVar(&c.Call, "call", c.Call, "")
	fs.BoolVar(&c.Hub, "hub", c.Hub, "")
	fs.BoolVar(&c.Tmux, "tmux", c.Tmux, "")
	fs.BoolVar(&c.Kuma, "kuma", c.Kuma, "")
	fs.IntVar(&c.KumaPort, "kuma-port", c.KumaPort, "")
	fs.StringVar(&c.KumaDir, "kuma-dir", c.KumaDir, "")
	fs.BoolVar(&c.Dashboard, "dashboard", c.Dashboard, "")
	fs.BoolVar(&c.Dashboard, "web-ui", c.Dashboard, "")
	fs.StringVar(&c.RunDir, "dir", c.RunDir, "") // working dir for `tshare run`/`host`
	fs.BoolVar(&c.Rar, "rar", c.Rar, "")
	fs.StringVar(&c.RarSize, "rar-size", c.RarSize, "")
	fs.StringVar(&c.STUN, "stun", c.STUN, "")
	fs.StringVar(&c.TURN, "turn", c.TURN, "")
	fs.StringVar(&c.TURNUser, "turn-user", c.TURNUser, "")
	fs.StringVar(&c.TURNPass, "turn-pass", c.TURNPass, "")
	fs.StringVar(&c.AbuseContact, "abuse-contact", c.AbuseContact, "")
	fs.BoolVar(&c.Legal, "legal", c.Legal, "")
	fs.BoolVar(&c.Transcode, "transcode", c.Transcode, "")
	fs.BoolVar(&c.Hevc, "hevc", c.Hevc, "")
	fs.BoolVar(&c.H265, "265", c.H265, "")
	fs.IntVar(&c.CQ, "cq", c.CQ, "")
	fs.BoolVar(&c.Heif, "heif", c.Heif, "")
	fs.BoolVar(&c.StripExif, "strip-exif", c.StripExif, "")
	fs.BoolVar(&c.NoGallery, "no-gallery", c.NoGallery, "")
	fs.BoolVar(&c.Encrypt, "encrypt", c.Encrypt, "")
	fs.BoolVar(&c.Copyparty, "copyparty", c.Copyparty, "")
	fs.BoolVar(&c.NoCopyparty, "no-copyparty", c.NoCopyparty, "")
	fs.StringVar(&c.CopypartyBin, "copyparty-bin", c.CopypartyBin, "")
	fs.StringVar(&c.CopypartyArgs, "copyparty-args", c.CopypartyArgs, "")
	fs.BoolVar(&c.LanHTTPS, "lan-https", c.LanHTTPS, "")
	fs.StringVar(&c.Profile, "profile", c.Profile, "")
	fs.StringVar(&c.Profile, "template", c.Profile, "") // --template = apply a saved preset
	fs.BoolVar(&c.NoConf, "no-config", c.NoConf, "")
	fs.BoolVar(&c.Watch, "watch", c.Watch, "")
	fs.BoolVar(&c.Persist, "persist", c.Persist, "")
	fs.BoolVar(&c.NoREPL, "no-repl", c.NoREPL, "")
	fs.BoolVar(&c.daemonChild, "__daemon", c.daemonChild, "")
	fs.StringVar(&c.daemonID, "__id", c.daemonID, "")
	fs.StringVar(&c.gameSidSeed, "__gamesid", c.gameSidSeed, "")
	fs.StringVar(&c.daemonTmp, "__tmp", c.daemonTmp, "")
	fs.StringVar(&c.daemonTmpDir, "__tmpdir", c.daemonTmpDir, "")
	fs.StringVar(&c.encKeyHex, "__enckey", c.encKeyHex, "")
}

// durFlag accepts 30m / 2h / 1d / 1w / never, and records explicit use.
type durFlag struct {
	d   *time.Duration
	set *bool
}

func (f *durFlag) String() string {
	if f.d == nil || *f.d == 0 {
		return ""
	}
	return f.d.String()
}
func (f *durFlag) Set(s string) error {
	d, err := parseDuration(s)
	if err != nil {
		return err
	}
	*f.d = d
	if f.set != nil {
		*f.set = true
	}
	return nil
}

func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "0" || s == "never" || s == "forever" {
		return 0, nil
	}
	mult := time.Duration(0)
	switch {
	case strings.HasSuffix(s, "d"):
		mult = 24 * time.Hour
	case strings.HasSuffix(s, "w"):
		mult = 7 * 24 * time.Hour
	}
	if mult > 0 {
		n, err := strconv.ParseFloat(s[:len(s)-1], 64)
		if err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(n * float64(mult)), nil
	}
	return time.ParseDuration(s)
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || s == "0" {
		return 0, nil
	}
	mult := int64(1)
	for suf, m := range map[string]int64{"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40} {
		if strings.HasSuffix(s, suf) || strings.HasSuffix(s, suf+"B") {
			mult = m
			s = strings.TrimSuffix(strings.TrimSuffix(s, "B"), suf)
			break
		}
	}
	n, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("bad size %q", s)
	}
	return int64(n * float64(mult)), nil
}

// rateLimiter is a simple token bucket (bytes/sec) shared by every connection
// of a share, so --max-rate caps aggregate served throughput. Stdlib-only: no
// golang.org/x/time/rate. It refills continuously and blocks callers until
// enough tokens accrue; a burst of one second's worth is allowed.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64 // max accumulated tokens
	tokens float64
	last   time.Time
}

func newRateLimiter(bytesPerSec int64) *rateLimiter {
	r := float64(bytesPerSec)
	// Keep the burst small (~100 ms of traffic, min 256 KiB) so the average
	// stays close to the target even on short transfers; a full second of burst
	// would let small downloads finish before the throttle ever bites.
	burst := r / 10
	if burst < 256<<10 {
		burst = 256 << 10
	}
	return &rateLimiter{rate: r, burst: burst, tokens: burst, last: time.Now()}
}

// wait blocks until n bytes may be sent. Requests larger than the burst are
// clamped to the burst so a single big Write can never deadlock.
func (l *rateLimiter) wait(n int) {
	if l == nil || l.rate <= 0 || n <= 0 {
		return
	}
	want := float64(n)
	if want > l.burst {
		want = l.burst
	}
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.last = now
		if l.tokens >= want {
			l.tokens -= want
			l.mu.Unlock()
			return
		}
		deficit := want - l.tokens
		l.mu.Unlock()
		d := time.Duration(deficit / l.rate * float64(time.Second))
		if d < time.Millisecond {
			d = time.Millisecond
		}
		time.Sleep(d)
	}
}

// diskFree returns the number of free bytes available on the filesystem that
// holds path (walking up to the nearest existing ancestor). unix-only.
func diskFree(path string) (int64, error) {
	for path != "" {
		if _, err := os.Stat(path); err == nil {
			break
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// parseArgs is lenient: flags may appear before or after positional args.
func parseArgs(args []string, c *config) error {
	for {
		fs := flag.NewFlagSet("tshare", flag.ContinueOnError)
		fs.Usage = func() { fmt.Fprint(os.Stderr, usageText) }
		registerFlags(fs, c)
		if err := fs.Parse(args); err != nil {
			return err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return nil
		}
		c.Paths = append(c.Paths, rest[0])
		args = rest[1:]
	}
}

// ---------------------------------------------------------------------------
// #71 config file & profiles

func configPath() string {
	if env := os.Getenv("TSHARE_CONFIG"); env != "" {
		return env
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "tshare", "config")
}

// applyConfig pre-seeds defaults from the config file (CLI flags still win).
func applyConfig(c *config, args []string) {
	if hasArg(args, "--no-config") {
		return
	}
	profile := argValue(args, "--profile")
	if profile == "" {
		profile = argValue(args, "--template") // templates are named presets (== profiles)
	}
	cfgArgs := loadConfigArgs(configPath(), profile)
	if len(cfgArgs) > 0 {
		fs := flag.NewFlagSet("config", flag.ContinueOnError)
		fs.SetOutput(io.Discard) // unknown config keys shouldn't dump usage
		registerFlags(fs, c)
		_ = fs.Parse(cfgArgs) // flags only; ignore unknown keys
	}
}

func hasArg(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

func argValue(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, name+"=") {
			return strings.TrimPrefix(a, name+"=")
		}
	}
	return ""
}

// loadConfigArgs turns the [default] section plus a named [profile] into a
// flag argv. Format: "key = value" lines, "# comments", "[section]" headers.
// Boolean keys may be bare ("encrypt") or "key = true/false".
func loadConfigArgs(path, profile string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	section := ""
	want := func() bool { return section == "" || section == "default" || (profile != "" && section == profile) }
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if !want() {
			continue
		}
		key, val, has := strings.Cut(line, "=")
		key = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(key), "--"))
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		if key == "" {
			continue
		}
		if !has || val == "" || val == "true" {
			out = append(out, "--"+key)
		} else if val == "false" {
			// omit
		} else {
			out = append(out, "--"+key, val)
		}
	}
	return out
}

// cmdTemplate manages share templates — named presets of flags stored as
// config sections (#25). Templates ARE config profiles; this just lets you
// save/list/remove them from the CLI instead of hand-editing the config, and
// apply one with `tshare --template <name> <path>`.
func cmdTemplate(args []string) {
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "save", "set":
		if len(args) < 2 || strings.HasPrefix(args[1], "-") {
			log.Fatal("usage: tshare template save <name> <flags…>   e.g. tshare template save client -p pw -e 7d --site")
		}
		name := args[1]
		if !validSlug(name) || name == "default" || name == "policy" {
			log.Fatalf("template name %q must be a simple slug (not 'default'/'policy')", name)
		}
		c := &config{}
		fs := flag.NewFlagSet("template", flag.ContinueOnError)
		registerFlags(fs, c)
		if err := fs.Parse(args[2:]); err != nil {
			log.Fatalf("tshare: %v", err)
		}
		var lines []string
		fs.Visit(func(f *flag.Flag) {
			if strings.HasPrefix(f.Name, "__") || f.Name == "template" || f.Name == "profile" {
				return
			}
			switch v := f.Value.String(); v {
			case "true":
				lines = append(lines, f.Name)
			case "false", "0", "":
				// off / empty → nothing to store
			default:
				lines = append(lines, f.Name+" = "+v)
			}
		})
		if len(lines) == 0 {
			log.Fatal("nothing to save — pass the flags this template should set")
		}
		sort.Strings(lines)
		if err := upsertConfigSection(name, lines); err != nil {
			log.Fatalf("tshare: %v", err)
		}
		fmt.Printf("  ✓ saved template [%s] → %s\n", name, configPath())
		fmt.Printf("  use it:  tshare --template %s <path>\n", name)
	case "ls", "list":
		names := configSections()
		if len(names) == 0 {
			fmt.Println("no templates yet — save one: tshare template save client -p pw -e 7d")
			return
		}
		fmt.Println("  templates (tshare --template <name> …):")
		for _, n := range names {
			fmt.Printf("    %s\n", n)
		}
	case "rm", "remove", "delete":
		if len(args) < 2 {
			log.Fatal("usage: tshare template rm <name>")
		}
		if err := upsertConfigSection(args[1], nil); err != nil {
			log.Fatalf("tshare: %v", err)
		}
		fmt.Printf("  ✓ removed template [%s]\n", args[1])
	default:
		fmt.Println("usage: tshare template save <name> <flags…>   save the flags as a reusable preset")
		fmt.Println("       tshare template ls                     list saved templates")
		fmt.Println("       tshare template rm <name>              delete one")
		fmt.Println("apply: tshare --template <name> <path>        (a template is a config profile)")
	}
}

// configSections lists the [named] sections in the config file, excluding the
// special [default] and [policy] blocks.
func configSections() []string {
	b, err := os.ReadFile(configPath())
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`(?m)^\[([^\]]+)\]\s*$`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		s := strings.TrimSpace(m[1])
		if s != "default" && s != "policy" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// upsertConfigSection replaces the [name] block with the given lines (creating
// the file/section if needed); nil lines removes the section entirely.
func upsertConfigSection(name string, lines []string) error {
	path := configPath()
	if path == "" {
		return errors.New("no config path")
	}
	existing, _ := os.ReadFile(path)
	text := string(existing)
	var block string
	if lines != nil {
		block = "[" + name + "]\n" + strings.Join(lines, "\n") + "\n"
	}
	secRe := regexp.MustCompile(`(?m)^\[` + regexp.QuoteMeta(name) + `\]\s*$`)
	if loc := secRe.FindStringIndex(text); loc != nil {
		rest := text[loc[1]:]
		end := len(text)
		if n := regexp.MustCompile(`(?m)^\[`).FindStringIndex(rest); n != nil {
			end = loc[1] + n[0]
		}
		text = text[:loc[0]] + block + text[end:]
	} else if lines != nil {
		if text == "" {
			text = "# tshare config (see config.example)\n"
		} else if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += "\n" + block
	} else {
		return nil // asked to remove a section that isn't there
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(text), 0o600)
}

// policy is optional, config-file-only org governance (#186). It lives in a
// [policy] section and is empty/inactive unless that section sets something.
type policy struct {
	maxExpires    time.Duration
	maxExpiresSet bool
	requirePw     bool
}

func (p policy) active() bool { return p.maxExpiresSet || p.requirePw }

// loadPolicy reads the [policy] section of the config file. Kept separate from
// loadConfigArgs (which maps keys→flags) because policy keys are not flags.
func loadPolicy(path string) policy {
	var p policy
	f, err := os.Open(path)
	if err != nil {
		return p
	}
	defer f.Close()
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "policy" {
			continue
		}
		key, val, _ := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch key {
		case "max_expires", "max-expires":
			if d, err := parseDuration(val); err == nil && d > 0 {
				p.maxExpires, p.maxExpiresSet = d, true
			}
		case "require_password", "require-password":
			p.requirePw = val == "" || val == "true"
		}
	}
	return p
}

func appendConfigKeys(kv map[string]string) error {
	path := configPath()
	if path == "" {
		return errors.New("no config path")
	}
	existing, _ := os.ReadFile(path)
	var add []string
	for k, v := range kv {
		re := regexp.MustCompile(`(?m)^(\s*(?:--)?` + regexp.QuoteMeta(k) + `\s*=\s*).*$`)
		if re.Match(existing) { // key already present → rewrite its value in place
			existing = re.ReplaceAll(existing, []byte("${1}"+v))
			continue
		}
		add = append(add, fmt.Sprintf("%s = %s", k, v))
	}
	if len(add) == 0 {
		return os.WriteFile(path, existing, 0o600) // may have updated values above
	}
	sort.Strings(add)
	block := "# recorded by tshare\n" + strings.Join(add, "\n") + "\n"
	var out string
	switch {
	case len(existing) == 0:
		out = "# tshare config (see config.example)\n[default]\n" + block
	default:
		lines := strings.SplitAfter(string(existing), "\n")
		at := -1 // insert index: after [default], else before the first section
		for i, l := range lines {
			t := strings.TrimSpace(l)
			if t == "[default]" {
				at = i + 1
				break
			}
			if strings.HasPrefix(t, "[") && at == -1 {
				at = i
				break
			}
		}
		if at == -1 { // no sections at all → append (still global)
			at = len(lines)
		}
		out = strings.Join(lines[:at], "") + block + strings.Join(lines[at:], "")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(out), 0o600)
}
