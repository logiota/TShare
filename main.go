//go:build unix

// tshare — secure secret-link file sharing over Tailscale Funnel.
//
// Default: `tshare <path>` serves a file/dir behind an unguessable token URL
// on the public internet via `tailscale funnel`. Lots of optional knobs:
// passwords, expiry, download limits, upload inboxes, zip, QR, tailnet-only,
// background mode, multi-share management (ls/rm), and a local/LAN mode.
//
// Single binary, stdlib only. macOS + Linux.
package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
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
	"sync/atomic"
	"syscall"
	"time"
)

const version = "1.10.0"

const usageText = `tshare v` + version + ` — secret-link file sharing over Tailscale Funnel

USAGE
  tshare [flags] <path> [path...]     share file(s)/folder(s), print secret link
  tshare [flags] <video-url>          download via yt-dlp, then share the file
  tshare -s http://localhost:8000     reverse-proxy a running local server
  tshare -                            share stdin (pipe)
  tshare -u [dir]                     inbox: link where others UPLOAD to you
  tshare -i                           blackhole inbox: accept & count uploads, keep nothing
  tshare set <id> [-p pw] [-e dur] [-n N]   change options on a RUNNING share
  tshare extend <id> [dur]            push out expiry (no dur = DOUBLE the time left)
  tshare info <id>                    live stats for a running share
  tshare ls [--json]                  list active shares
  tshare rm <id>... | --all           stop share(s), remove funnel mount
  tshare panic                        kill ALL shares NOW & wipe every token/state
  tshare resume                       restart shares saved with --persist
  tshare decrypt [-p pw] <f.enc>...   decrypt files received by an --encrypt inbox
  tshare doctor                       check tailscale / funnel / tools
  tshare version                      print version

  While a foreground share runs you can TYPE options to change it live, e.g.
  "-p secret", "-e 2d", "-x" (double expiry), "-n 5", "--no-password", "info", "stop".

MEDIA
  Images/video/audio play in the browser (streamable, seekable); every folder
  row also has a ⬇ direct-download link. Append ?dl=1 to any file URL to force
  download. --inline forces in-browser viewing for all types. Sibling subtitles
  (movie.srt / movie.en.vtt) and a poster image are auto-added to the player;
  .srt is converted to WebVTT on the fly.

YT-DLP (built in — pass any yt-dlp-supported URL)
  tshare "https://youtube.com/watch?v=…"     download → share an iOS-ready mp4
  tshare -a "https://…"                      audio only → share an mp3
  tshare --playlist "https://…/playlist…"    whole playlist → share as a folder
  tshare --yt-format "bv*+ba" "https://…"    pass a custom -f format to yt-dlp
  tshare --yt-args "--cookies c.txt" "https://…"   extra raw yt-dlp args
  Single-file: the link + QR print immediately; the download runs in the
  background and visitors get a self-refreshing "downloading… N%" page until the
  file is ready (playlists still publish only after the fetch finishes). Default
  picks an H.264/AAC MP4 (remuxed) so it streams + seeks on iOS. Needs yt-dlp on PATH.

PIPES (share the result of any command once it finishes)
  yt-dlp -o - "https://…" | tshare - --filename video.mp4
  tar czf - project/      | tshare - --filename project.tgz -e 2h
  The share starts when stdin hits EOF. Without --filename the type is sniffed
  (mp4/webm/mp3/png/… ) and named automatically.

SECURITY FLAGS
  -p, --password <pw>     require a password (HTTP Basic; curl -u :<pw>)
                          (or set env TSHARE_PASSWORD)
  -e, --expires <dur>     auto-stop after: 30m, 2h, 1d, 1w, never
                          (default: 15d; changeable later via tshare set)
  -n, --max <N>           stop after N completed downloads
      --once              shorthand for -n 1 (burn after reading)
      --max-bytes <sz>    stop after ~this many bytes served (1.5× hard ceiling)
      --max-rate <sz>     throttle served bandwidth, e.g. 2M = ~2 MB/s (default: off)
      --min-free <sz>     refuse uploads when free disk space < this (default 32G; 0=off)
      --require-identity  funnel: require a Tailscale login (blocks anon public)
      --encrypt           encrypt received uploads at rest (AES-256-GCM)
      --abuse-contact <s> show a small-font takedown/abuse line on public pages
      --token-len <n>     secret token length, default 16 (~95 bits)
      --name <slug>       vanity path instead of random token (weaker secrecy!)

MODES
  -t, --tailnet           tailnet-only (tailscale serve) instead of public funnel
  -u, --upload [dir]      inbox mode: receive files into dir (default ./tshare-inbox)
  -i, --blackhole         write-only sink: uploads are read, counted & notified,
                          but the bytes are discarded (nothing hits disk). Best
                          over the printed 'lan' URL for a direct throughput test.
      --allow-upload      folder share also accepts uploads (collaboration)

FOLDER ENGINE
  Single-folder browse/upload/inbox shares are handled by copyparty (resumable
  uploads, dedup, thumbnails, WebDAV) when it's installed — reverse-proxied
  behind tshare's token/password/expiry/limits. Falls back to the native folder
  server automatically. Single files & media stay native (iOS player, transcode).
      --copyparty         force copyparty (error if missing)
      --no-copyparty      always use the native folder server
      --copyparty-bin <p> copyparty binary or copyparty-sfx.py (or env TSHARE_COPYPARTY)
      --copyparty-args    extra raw copyparty args
  -z, --zip               serve a folder as a single .zip download
      --site, --web       serve a folder as a LIVE static website: index.html is
                          rendered, every file opens in-browser (not downloaded),
                          and folders without an index get a browsable listing.
                          Scripts run (no sandbox); expiry defaults to never.
                          Pair with --name for a stable /<name>/ path
  -l, --local             no tailscale: plain HTTP on your LAN (testing/offline)
      --lan-https         --local: serve HTTPS with a self-signed cert
      --no-lan            funnel/serve only — don't also expose on the LAN
                          (by default a share is ALSO reachable directly on your
                          LAN via http://<lan-ip>:<port>/<token>, token-gated)
      --watch             watch a shared folder; announce new files as they land
      --persist           remember this share so 'tshare resume' restarts it
      --profile <name>    use a [name] section from ~/.config/tshare/config
      --no-config         ignore the config file
      --inline            display in browser instead of forcing download
  -Y, --yt-dlp            force treating the argument as a yt-dlp URL
  -a, --yt-audio          yt-dlp: smart audio-only → tagged M4A (cover art)
      --yt-format <f>     yt-dlp: -f format selector
      --yt-args "<args>"  yt-dlp: extra raw args (quoted)
      --playlist          yt-dlp: download the whole playlist (→ folder share)
      --fetch             plain HTTP download (wget-style) instead of yt-dlp
      --progressive       serve while it downloads (stdin or URL)
      --live              live stream: progressive, ends when the source does
  -s, --server            reverse-proxy a running server URL over the funnel
                          (auto for localhost URLs; rewrites Host, passes
                          WebSockets; use relative asset paths under /<token>/)

MEDIA TRANSFORMS (need ffmpeg / sips / imagemagick on PATH)
      --transcode         re-encode video to a clean, streamable MP4
      --hevc              transcode target is H.265/HEVC (hardware-accelerated)
      --265               hardware HEVC to a temp file at constant quality
                          (implies --transcode --hevc; size floats to hit quality)
      --cq <n>            constant-quality for --265 (default 50). Encoder-native
                          scale: x265/NVENC lower=better; Apple VideoToolbox higher=better
      --heif              convert HEIC/HEIF images to JPEG for viewing
      --strip-exif        remove EXIF/metadata from served JPEGs
      --no-gallery        disable the photo lightbox on image folders

OUTPUT & LIFECYCLE
  -b, --bg                run in background (manage with tshare ls / set / rm)
      --filename <name>   public file name (stdin shares & single-file renames)
  -q, --qr                QR code — ON by default when qrencode is installed
  -c, --copy              copy link to clipboard — ON by default
      --no-qr             disable the QR code
      --no-copy           don't touch the clipboard
      --no-notify         disable desktop notifications (uploads received;
                          invalid/unauthorized access attempts with IP + URL)
      --open              also open the link in your browser
      --quiet             print only the URL (also mutes QR auto-display)
      --json              print share metadata as JSON
      --max-upload <sz>   per-request upload limit, e.g. 500M, 2G (default 5G)
      --https-port <p>    funnel public port: 443, 8443, 10000 (default 443)
      --port <p>          pin local backend port (default: auto)
      --tailscale-bin <p> path to tailscale CLI (or env TAILSCALE)

EXAMPLES
  tshare report.pdf                      simplest: public secret link
  tshare -p hunter2 -e 24h ~/Designs     password + 24h expiry, browsable folder
  tshare --once secrets.env              link dies after first download
  tshare -z -e 1w ~/Photos/trip          one-week link to a zip of the folder
  tshare -u -e 2d                        2-day upload inbox (drop-box)
  tshare --allow-upload -p s3cret ~/proj shared folder: browse + upload
  tshare --site ~/blog                   serve a static website over funnel
  tshare -s http://localhost:5173        share your running dev server
  tshare "https://youtu.be/…"            yt-dlp download → iOS-ready mp4 link
  tshare -t plan.md                      tailnet-only (not public)
  tshare -b bigfile.iso                  background; later: tshare ls / set / rm
  tshare set a1b2c3 -p newpw -e never    change a running share's options
  tshare rm a1b2c3                       stop one; tshare rm --all stops all
`

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
	YtDlp     bool   // force treating the input as a yt-dlp URL
	YtFormat  string // -f passthrough
	YtArgs    string // extra raw yt-dlp args (shell-split)
	YtAudio   bool   // extract audio → m4a/mp3 (smart)
	Playlist  bool   // allow playlists (default: single video)
	Fetch     bool   // force plain HTTP fetch (wget-style) instead of yt-dlp
	Progress  bool   // start serving while the download is still running
	Live      bool   // live stream: progressive + no length, ends at producer EOF
	Server    bool   // reverse-proxy an already-running local server (URL)

	// access & limits
	RequireID bool   // funnel: require an authenticated Tailscale identity
	MaxBytes  string // total bytes served before the link stops (e.g. 2G)
	MaxRate   string // per-share bandwidth cap for served bytes (e.g. 2M = 2 MB/s; "" = unlimited)
	MinFree   string // refuse uploads when free disk space drops below this (default 32G; 0 = off)

	// inbox / blackhole
	Blackhole bool // -i: accept + count uploads but discard the bytes (throughput sink)

	// abuse / legal
	AbuseContact string // small-font takedown/abuse contact shown on public share pages ("" = hidden)

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
	NoConf  bool   // skip reading the config file
	Watch   bool   // watch a directory and auto-share new files
	Persist bool   // record share so `tshare resume` can restart it after reboot
	NoREPL  bool   // disable the interactive option prompt in the foreground

	// internal
	daemonChild  bool
	daemonID     string
	daemonTmp    string // temp file the daemon child must delete on exit
	daemonTmpDir string // temp dir the daemon child must delete on exit
	encKeyHex    string // passed to bg child so it inherits the inbox key
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
	fs.StringVar(&c.AbuseContact, "abuse-contact", c.AbuseContact, "")
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
	fs.BoolVar(&c.NoConf, "no-config", c.NoConf, "")
	fs.BoolVar(&c.Watch, "watch", c.Watch, "")
	fs.BoolVar(&c.Persist, "persist", c.Persist, "")
	fs.BoolVar(&c.NoREPL, "no-repl", c.NoREPL, "")
	fs.BoolVar(&c.daemonChild, "__daemon", c.daemonChild, "")
	fs.StringVar(&c.daemonID, "__id", c.daemonID, "")
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
	mu       sync.Mutex
	rate     float64 // bytes per second
	burst    float64 // max accumulated tokens
	tokens   float64
	last     time.Time
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
// entry

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "ls", "list":
			cmdLs(args[1:])
			return
		case "rm", "stop", "revoke":
			cmdRm(args[1:])
			return
		case "set":
			cmdSet(args[1:])
			return
		case "extend", "-x":
			cmdExtend(args[1:])
			return
		case "panic", "--panic":
			cmdPanic()
			return
		case "info":
			cmdInfo(args[1:])
			return
		case "doctor":
			cmdDoctor()
			return
		case "decrypt":
			cmdDecrypt(args[1:])
			return
		case "resume":
			cmdResume(args[1:])
			return
		case "version", "--version", "-v":
			fmt.Println("tshare v" + version)
			return
		case "help", "--help", "-h":
			fmt.Print(usageText)
			return
		}
	}

	c := &config{TokenLen: 16, HTTPSPort: 443, MaxUpload: "5G", MinFree: "32G", CQ: 50,
		Copy: true, LAN: true, Password: os.Getenv("TSHARE_PASSWORD")}
	// config file (#71): defaults < config file/profile < CLI flags
	applyConfig(c, args)
	if err := parseArgs(args, c); err != nil {
		os.Exit(2)
	}
	if c.Once {
		c.MaxDL = 1
	}
	if c.Live {
		c.Progress = true // live implies progressive serving
	}
	if c.H265 { // --265: hardware HEVC to a temp file at constant quality
		c.Transcode, c.Hevc = true, true
		if c.CQ <= 0 || c.CQ > 63 {
			c.CQ = 50
		}
	}
	if err := runShare(c); err != nil {
		log.Fatalf("tshare: %v", err)
	}
}

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

	dl        atomic.Int64
	upCount   atomic.Int64
	shutdown  chan string
	stateMu   sync.Mutex
	lastPort  int
	lastStateWrite time.Time // throttle for state-file writes
	stateDirty     bool
	probeMu   sync.Mutex
	lastProbe time.Time
	probeHeld int

	maxBytes   int64        // #13: stop after this many bytes served (0 = ∞)
	bytesServed atomic.Int64 // cumulative response bytes for the byte cap
	blackhole  bool         // -i: discard uploaded bytes (throughput sink, nothing on disk)
	minFree    int64        // refuse uploads when free disk bytes fall below this (0 = off)
	limiter    *rateLimiter // --max-rate: shared token bucket throttling served bytes (nil = off)
	viewers    atomic.Int64 // #61: in-flight viewers (presence)
	encKey     []byte       // #10: AES-256 key for at-rest inbox encryption
	grow       *growing     // #49: progressive/live source still being written
	ytPend     *ytPending   // yt-dlp download still running: hold visitors until ready
	afterAnnounce func()    // run once after the link/QR is printed (e.g. start the yt-dlp download)

	cpCmd   *exec.Cmd            // copyparty subprocess (folder engine), if used
	cpProxy *httputil.ReverseProxy // reverse proxy to copyparty on loopback
	cpPort  int

	srvProxy *httputil.ReverseProxy // -s: reverse proxy to a user-run server
	srvURL   string                 // its target URL (for display)
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
	// Websites are long-term by nature, so --site defaults to never.
	if !c.ExpiresSet && c.Expires == 0 && !c.Site {
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
	oneInput := !c.Upload && !c.Blackhole && len(c.Paths) == 1
	// -s, or a localhost URL ("automatically if it is not a website"), means
	// reverse-proxy a running server rather than download it.
	serverMode := oneInput && looksLikeURL(c.Paths[0]) && (c.Server || isLocalServerURL(c.Paths[0]))
	fetchMode := oneInput && c.Fetch && !serverMode && looksLikeURL(c.Paths[0])
	ytMode := oneInput && !c.Fetch && !serverMode && (c.YtDlp || looksLikeURL(c.Paths[0]))
	switch {
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
	}
	defer cleanup()

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

func (s *share) announce(port int) {
	c := s.cfg
	link := s.prettyURL()
	if c.JSON {
		meta := map[string]any{
			"id": s.id, "url": link, "base": s.baseURL + "/", "mode": s.mode,
			"token": s.token, "port": port, "password": c.Password != "",
			"tailnet_only": c.Tailnet, "local": c.Local,
			"max_downloads": c.MaxDL, "pid": os.Getpid(),
		}
		if t := s.getExpires(); !t.IsZero() {
			meta["expires_at"] = t.Format(time.RFC3339)
		}
		j, _ := json.MarshalIndent(meta, "", "  ")
		fmt.Println(string(j))
	} else if c.Quiet {
		fmt.Println(link)
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
		linkExtras(c, link)
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
	case "inbox":
		return "curl " + auth + "-F f=@file.txt " + s.baseURL + "/__upload"
	default:
		return "curl " + auth + "-o all.zip " + s.baseURL + "/__zip"
	}
}

// ---------------------------------------------------------------------------
// HTTP handler

type respRec struct {
	http.ResponseWriter
	status  int
	bytes   int64
	limiter *rateLimiter // --max-rate throttle (nil = unlimited)
}

func (r *respRec) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}
func (r *respRec) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	r.limiter.wait(len(b)) // no-op when nil / unlimited
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

// Flush forwards to the underlying writer so progressive/live streaming works.
func (r *respRec) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *share) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &respRec{ResponseWriter: w, limiter: s.limiter}
	start := time.Now()
	s.viewers.Add(1) // #61 presence: in-flight viewers
	defer s.viewers.Add(-1)
	who := r.Header.Get("X-Forwarded-For")
	if who == "" {
		who = r.RemoteAddr
	}
	// A tailnet identity is injected by tailscaled only for authenticated tailnet
	// users coming through the secret mount — not anonymous public Funnel hits. A
	// 404/401 from such a known person is a typo or a stale link, not a scanner
	// probing us, so it shouldn't raise the ⚠ marker or an "invalid access" alert.
	authed := r.Header.Get("Tailscale-User-Login") != ""
	if u := r.Header.Get("Tailscale-User-Login"); u != "" {
		who += " (" + u + ")"
	}
	defer func() {
		// #13 byte cap: tally served bytes; stop at the 1.5× hard ceiling
		if s.maxBytes > 0 && rec.bytes > 0 {
			if s.bytesServed.Add(rec.bytes) >= s.maxBytes*3/2 {
				s.trigger("byte cap reached (1.5×)")
			}
		}
	}()
	defer func() {
		suspicious := !authed && (rec.status == http.StatusNotFound ||
			rec.status == http.StatusUnauthorized || rec.status == http.StatusGone)
		if !s.cfg.Quiet {
			mark := ""
			if suspicious {
				mark = "  ⚠"
			}
			log.Printf("%s %s %s → %d  %s  %s  %s%s",
				start.Format("15:04:05"), r.Method, s.redact(r.URL.Path),
				rec.status, humanSize(rec.bytes), time.Since(start).Round(time.Millisecond), who, mark)
		}
		if suspicious {
			s.probeAlert(who, r.Method, r.URL.Path, rec.status)
		}
	}()

	h := rec.Header()
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")

	if s.expired() {
		http.Error(rec, "410 link expired", http.StatusGone)
		s.trigger("expired")
		return
	}
	// #13: refuse new transfers once the byte cap is hit (in-flight ones may
	// finish up to the 1.5× ceiling enforced in the deferred tally above).
	if s.maxBytes > 0 && s.bytesServed.Load() >= s.maxBytes {
		http.Error(rec, "410 transfer limit reached", http.StatusGone)
		return
	}

	// Token gate. funnel/serve traffic is proxied in by the local tailscaled
	// over loopback, and Tailscale strips the --set-path prefix, so those
	// requests arrive token-LESS but trusted (tailscaled already matched the
	// secret mount). A DIRECT connection — any LAN peer hitting the bound
	// port, or anything in --local mode — is NOT proxied, so it must present
	// the token in the path. This keeps the LAN URL just as secret-gated as
	// the funnel one.
	proxied := !s.cfg.Local && remoteIsLoopback(r.RemoteAddr)
	p := strings.TrimPrefix(r.URL.Path, "/")
	seg, rest, _ := strings.Cut(p, "/")
	if subtle.ConstantTimeCompare([]byte(seg), []byte(s.token)) == 1 {
		p = rest // token present → strip it
	} else if !proxied {
		http.NotFound(rec, r) // direct hit without the token
		return
	}

	// #8: require an authenticated Tailscale identity. tailscaled injects
	// Tailscale-User-Login for tailnet requests but NOT for anonymous public
	// Funnel hits, so this gates a funnel mount to tailnet users only. Only
	// enforced for proxied (tailscaled) requests; direct LAN hits rely on the
	// token (they carry no Tailscale identity at all).
	if s.cfg.RequireID && proxied && r.Header.Get("Tailscale-User-Login") == "" {
		http.Error(rec, "403 tailnet identity required (Funnel public access blocked)", http.StatusForbidden)
		return
	}

	// optional password (HTTP Basic, any username)
	if want := s.getPassword(); want != "" {
		_, pw, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pw), []byte(want)) != 1 {
			rec.Header().Set("WWW-Authenticate", `Basic realm="tshare"`)
			http.Error(rec, "401 password required", http.StatusUnauthorized)
			return
		}
	}

	rel := strings.Trim(path.Clean("/"+p), "/") // ""=root, no dot-dots

	// copyparty folder engine: forward everything (browse, upload, WebDAV,
	// thumbnails, any method) to copyparty on loopback, normalising the path to
	// its volume location /<token>/<rel> so its links stay consistent whether
	// the request arrived via Funnel (token stripped) or LAN (token present).
	if s.cpProxy != nil {
		target := "/" + s.token
		if rel != "" {
			target += "/" + rel
		}
		r.URL.Path = target
		r.URL.RawPath = ""
		s.cpProxy.ServeHTTP(rec, r)
		return
	}

	// -s: reverse-proxy to a user-run server. Forward the token-stripped path
	// straight through (the upstream expects root-relative paths), preserving
	// method, body, query and WebSocket upgrades.
	if s.srvProxy != nil {
		r.URL.Path = "/" + rel
		r.URL.RawPath = ""
		s.srvProxy.ServeHTTP(rec, r)
		return
	}

	// #site: serve the folder as a live website (index.html routing, real
	// content-types, scripts allowed). Owns all routing — no upload/zip.
	if s.mode == "site" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(rec, "405 method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.serveSite(rec, r, rel)
		return
	}

	// special endpoints (work at root and inside subfolders)
	if rel == "__upload" || strings.HasSuffix(rel, "/__upload") {
		s.handleUpload(rec, r, strings.TrimSuffix(strings.TrimSuffix(rel, "__upload"), "/"))
		return
	}
	if rel == "__zip" || strings.HasSuffix(rel, "/__zip") {
		s.handleZip(rec, r, strings.TrimSuffix(strings.TrimSuffix(rel, "__zip"), "/"))
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(rec, "405 method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Page links are absolute and must point at the host the visitor is using:
	// the LAN URL for a direct LAN visitor, the funnel/tailnet URL otherwise.
	urlBase := s.baseURL
	if !proxied && s.lanURL != "" {
		urlBase = s.lanURL
	}

	switch s.mode {
	case "inbox":
		if rel != "" {
			http.NotFound(rec, r)
			return
		}
		s.renderInbox(rec, urlBase)
	case "file":
		s.serveFile(rec, r, s.roots[0].Abs, s.roots[0].Name)
	case "dir", "multi":
		if rel == "" && s.cfg.Zip {
			s.handleZip(rec, r, "")
			return
		}
		abs, isDir, ok := s.resolve(rel)
		if !ok {
			http.NotFound(rec, r)
			return
		}
		if isDir {
			s.renderDir(rec, rel, abs, urlBase)
		} else {
			s.serveFile(rec, r, abs, path.Base("/"+rel))
		}
	}
}

// escPath escapes each segment of a slash-separated rel path for use in URLs.
func escPath(rel string) string {
	segs := strings.Split(rel, "/")
	for i, sg := range segs {
		segs[i] = url.PathEscape(sg)
	}
	return strings.Join(segs, "/")
}

func (s *share) redact(p string) string {
	if s.cfg.Name == "" && len(s.token) > 6 {
		return strings.Replace(p, s.token, s.token[:4]+"…", 1)
	}
	return p
}

// resolve maps a cleaned rel path to an absolute path, confined to the roots.
func (s *share) resolve(rel string) (abs string, isDir bool, ok bool) {
	if s.mode == "multi" {
		if rel == "" {
			return "", true, true // virtual root listing
		}
		head, tail, _ := strings.Cut(rel, "/")
		for _, e := range s.roots {
			if e.Name != head {
				continue
			}
			if !e.IsDir {
				if tail != "" {
					return "", false, false
				}
				return e.Abs, false, true
			}
			return s.confined(e.Abs, tail)
		}
		return "", false, false
	}
	return s.confined(s.roots[0].Abs, rel)
}

func (s *share) confined(root, rel string) (string, bool, bool) {
	// hidden files/dirs are not exposed inside shared folders
	for _, seg := range strings.Split(rel, "/") {
		if strings.HasPrefix(seg, ".") && seg != "" {
			return "", false, false
		}
	}
	abs := filepath.Join(root, filepath.FromSlash(rel))
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", false, false
	}
	if real != root && !strings.HasPrefix(real, root+string(filepath.Separator)) {
		return "", false, false
	}
	fi, err := os.Stat(real)
	if err != nil {
		return "", false, false
	}
	return real, fi.IsDir(), true
}

// resolveSite validates the --site target and returns the web root + default
// document. A folder is served as-is; a single .html serves its parent folder.
func resolveSite(paths []string) (root, index string, err error) {
	if len(paths) != 1 {
		return "", "", errors.New("--site takes exactly one folder (or one .html file)")
	}
	abs, err := filepath.Abs(paths[0])
	if err != nil {
		return "", "", err
	}
	if abs, err = filepath.EvalSymlinks(abs); err != nil {
		return "", "", err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return "", "", err
	}
	if fi.IsDir() {
		return abs, "index.html", nil
	}
	if ext := strings.ToLower(filepath.Ext(abs)); ext != ".html" && ext != ".htm" {
		return "", "", errors.New("--site needs a folder or an .html file")
	}
	// a lone .html: serve its folder as the root (so sibling assets load)
	return filepath.Dir(abs), filepath.Base(abs), nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// siteContentType returns an explicit, correct MIME type for web assets — vital
// because tshare sends X-Content-Type-Options: nosniff, so a wrong/empty type
// would make the browser refuse to run scripts/styles.
func siteContentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".json", ".map":
		return "application/json; charset=utf-8"
	case ".svg":
		return "image/svg+xml"
	case ".wasm":
		return "application/wasm"
	case ".webmanifest", ".manifest":
		return "application/manifest+json"
	case ".xml":
		return "application/xml; charset=utf-8"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".ico":
		return "image/x-icon"
	}
	return mime.TypeByExtension(strings.ToLower(filepath.Ext(name)))
}

// serveSite routes a request within a --site share: directories resolve to
// index.html, missing paths fall back to 404.html if present, and assets are
// served inline with correct types and NO download/sandbox so the site runs.
func (s *share) serveSite(w *respRec, r *http.Request, rel string) {
	root := s.roots[0].Abs
	abs, isDir, ok := s.confined(root, rel)
	if !ok {
		if p := filepath.Join(root, "404.html"); fileExists(p) {
			if b, err := os.ReadFile(p); err == nil {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusNotFound)
				w.Write(b)
				return
			}
		}
		http.NotFound(w, r)
		return
	}
	if isDir {
		idx := filepath.Join(abs, s.siteIndex)
		if !fileExists(idx) {
			idx = filepath.Join(abs, "index.htm")
		}
		if !fileExists(idx) {
			s.renderSiteList(w, rel, abs) // no index → browsable listing
			return
		}
		abs = idx
	}
	f, err := os.Open(abs)
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
	if ct := siteContentType(abs); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	// ServeContent adds Last-Modified + ETag and handles Range/If-Modified-Since
	// (304) — good caching for a long-lived site, with no forced download.
	http.ServeContent(w, r, filepath.Base(abs), fi.ModTime(), f)
}

// renderSiteList shows a minimal browsable listing for a --site folder that has
// no index.html. Links are token-prefixed root-absolute URLs so they resolve
// under Funnel (token stripped) and LAN (token present) alike, and every file
// opens rendered inline (html as a page, images/pdf/text shown — not downloaded).
func (s *share) renderSiteList(w *respRec, rel, absDir string) {
	des, err := os.ReadDir(absDir)
	if err != nil {
		http.Error(w, "500 cannot list folder", http.StatusInternalServerError)
		return
	}
	esc := template.HTMLEscapeString
	href := func(name string) string {
		rp := name
		if rel != "" {
			rp = rel + "/" + name
		}
		return "/" + s.token + "/" + escPath(rp)
	}
	var dirs, files []string
	for _, de := range des {
		if strings.HasPrefix(de.Name(), ".") {
			continue
		}
		if de.IsDir() {
			dirs = append(dirs, de.Name())
		} else {
			files = append(files, de.Name())
		}
	}
	sort.Strings(dirs)
	sort.Strings(files)

	title := "/"
	if rel != "" {
		title = "/" + rel + "/"
	}
	var b strings.Builder
	b.WriteString(`<!doctype html><html><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<meta name="robots" content="noindex,nofollow"><title>` + esc(title) + `</title>`)
	b.WriteString(`<style>:root{color-scheme:dark light}body{font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:760px;margin:0 auto;padding:28px 18px}` +
		`h1{font-size:16px;font-weight:650}a{text-decoration:none;color:#4f63ff}a:hover{text-decoration:underline}` +
		`li{list-style:none;padding:5px 0;border-bottom:1px solid #8884}ul{padding:0;margin:14px 0}.d{font-weight:600}</style></head><body>`)
	b.WriteString(`<h1>📁 ` + esc(title) + `</h1><ul>`)
	if rel != "" {
		parent := path.Dir(rel)
		up := "/" + s.token + "/"
		if parent != "." && parent != "" {
			up += escPath(parent) + "/"
		}
		b.WriteString(`<li><a href="` + up + `">⬆ ..</a></li>`)
	}
	for _, d := range dirs {
		b.WriteString(`<li><a class="d" href="` + href(d) + `/">📁 ` + esc(d) + `/</a></li>`)
	}
	for _, f := range files {
		b.WriteString(`<li><a href="` + href(f) + `">📄 ` + esc(f) + `</a></li>`)
	}
	if len(dirs)+len(files) == 0 {
		b.WriteString(`<li style="color:#8888">empty folder</li>`)
	}
	b.WriteString(`</ul></body></html>`)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

// serveDownloading holds a visitor while a backgrounded yt-dlp download runs:
// a 503 with Retry-After, plus a self-refreshing percentage page for browsers
// and a plain line for curl/wget.
func (s *share) serveDownloading(w http.ResponseWriter, r *http.Request, pct float64, wantsHTML bool) {
	w.Header().Set("Retry-After", "2")
	w.Header().Set("Cache-Control", "no-store")
	if wantsHTML {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	if r.Method == http.MethodHead {
		return
	}
	if !wantsHTML {
		fmt.Fprintf(w, "downloading %.0f%%\n", pct)
		return
	}
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8">`+
		`<meta name="viewport" content="width=device-width,initial-scale=1">`+
		`<meta name="robots" content="noindex,nofollow"><meta http-equiv="refresh" content="2">`+
		`<title>downloading… %.0f%%</title>`+
		`<style>:root{color-scheme:dark light}body{font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;`+
		`max-width:520px;margin:0 auto;padding:48px 18px;text-align:center}`+
		`h1{font-size:17px;font-weight:650}`+
		`.bar{height:10px;border-radius:6px;background:#8884;overflow:hidden;margin:18px 0}`+
		`.bar>i{display:block;height:100%%;width:%.1f%%;background:#4f63ff;transition:width .4s}`+
		`.pct{font-variant-numeric:tabular-nums;font-weight:600}</style></head><body>`+
		`<h1>⬇ Downloading…</h1><div class="bar"><i></i></div>`+
		`<p class="pct">%.0f%%</p><p style="color:#8888">this page refreshes automatically</p>`+
		`</body></html>`, pct, pct, pct)
}

func (s *share) serveFile(w *respRec, r *http.Request, abs, name string) {
	q := r.URL.Query()
	dl := q.Get("dl") == "1"
	raw := q.Get("raw") == "1"
	wantsHTML := strings.Contains(r.Header.Get("Accept"), "text/html")

	// yt-dlp single-file share: the download started after the link went live.
	// Hold visitors with a self-refreshing percentage page until it's ready.
	if s.ytPend != nil {
		pct, done, err := s.ytPend.state()
		if !done {
			s.serveDownloading(w, r, pct, wantsHTML)
			return
		}
		if err != nil {
			http.Error(w, "502 download failed", http.StatusBadGateway)
			return
		}
		// done OK → roots[0] now points at the finished file; fall through.
		abs, name = s.roots[0].Abs, s.roots[0].Name
	}

	// #49 progressive/live: the file is still being written. Serve the media
	// player page for a browser, else stream the growing bytes from ?raw=1.
	if s.grow != nil {
		if isMedia(name) && !dl && !raw && wantsHTML && r.Method == http.MethodGet {
			s.renderMediaPage(w, r, "", name)
			return
		}
		s.grow.serve(w, r, name, !dl && (raw || s.cfg.Inline || isMedia(name)))
		return
	}

	// media transforms (#33 strip-exif, #35 transcode/HEVC, HEIF→JPEG)
	abs, name = s.maybeTransform(abs, name)

	// subtitles: serve .srt converted to WebVTT (and .vtt as-is) so the
	// player's <track> works in every browser.
	if ext := strings.ToLower(filepath.Ext(name)); !dl && (ext == ".srt" || ext == ".vtt") {
		s.serveSubtitle(w, abs, ext)
		return
	}

	f, err := os.Open(abs)
	if err != nil {
		http.Error(w, "404 not found", http.StatusNotFound)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}

	// A single shared .html/.htm renders as a real web page (scripts enabled) —
	// "share this html" almost always means "let them view it", and these are
	// usually self-contained apps. Only for a single-FILE share; .html inside a
	// shared folder still downloads on click (file-manager behaviour). ?dl=1
	// forces download. Use a folder + --site for multi-file sites.
	if s.mode == "file" && !dl && !raw {
		if e := strings.ToLower(filepath.Ext(name)); e == ".html" || e == ".htm" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			http.ServeContent(w, r, name, fi.ModTime(), f)
			if r.Method == http.MethodGet && w.status == http.StatusOK {
				s.countDownload()
			}
			return
		}
	}

	// For media, a top-level browser navigation gets a styled player PAGE
	// (so iOS Safari shows a real, full-size, seekable player instead of a
	// bare quirk-mode media element). The page's <video>/<audio>/<img> then
	// streams the bytes from ?raw=1. Direct download (?dl=1), the raw stream
	// (?raw=1), and non-browser clients (curl) get the bytes directly.
	if isMedia(name) && !dl && !raw && wantsHTML && r.Method == http.MethodGet {
		s.renderMediaPage(w, r, abs, name)
		return
	}

	// disposition: media + --inline view in-browser; everything else downloads.
	disp := "attachment"
	switch {
	case dl:
		// explicit download wins
	case raw, s.cfg.Inline, isMedia(name):
		disp = "inline"
		// sandbox: never execute active content (e.g. uploaded HTML/SVG)
		w.Header().Set("Content-Security-Policy", "sandbox")
	}
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disp, map[string]string{"filename": name}))
	// iOS needs an accurate Content-Type for <video>/<audio> + Range to work;
	// http.ServeContent infers from extension, but set it for sniffed/unknown.
	if ct := mediaContentType(name); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Accept-Ranges", "bytes")
	http.ServeContent(w, r, name, fi.ModTime(), f) // handles Range + 206 itself
	// count a download only on a full 200 GET, not partial 206 range chunks,
	// so a seeking video player isn't counted as many downloads.
	if r.Method == http.MethodGet && w.status == http.StatusOK {
		s.countDownload()
	}
}

// mediaContentType returns an explicit MIME type for media (incl. types Go's
// mime package may miss), or "" to let http.ServeContent infer it.
func mediaContentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".mp4", ".m4v":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mov":
		return "video/quicktime"
	case ".mkv":
		return "video/x-matroska"
	case ".m4a":
		return "audio/mp4"
	case ".mp3":
		return "audio/mpeg"
	case ".aac":
		return "audio/aac"
	case ".ogg", ".opus":
		return "audio/ogg"
	case ".wav":
		return "audio/wav"
	case ".flac":
		return "audio/flac"
	}
	return ""
}

// mediaKind buckets a filename for the player page: video | audio | image.
func mediaKind(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".mp4", ".webm", ".mov", ".m4v", ".mkv":
		return "video"
	case ".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac":
		return "audio"
	default:
		return "image"
	}
}

type subTrack struct{ Src, Label, Default string }

func (s *share) renderMediaPage(w *respRec, r *http.Request, abs, name string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var tracks []subTrack
	poster := ""
	// In folder mode the siblings of the media file are reachable through the
	// same share, so pull in subtitle tracks and a poster image next to it.
	if abs != "" && (s.mode == "dir" || s.mode == "multi") {
		tracks, poster = s.siblings(abs, name)
	}
	data := map[string]any{
		"Name": name, "Kind": mediaKind(name), "Type": mediaContentType(name),
		"Tracks": tracks, "Poster": poster, "Abuse": s.abuseHTML(),
	}
	if err := mediaTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

// siblings finds subtitle and poster files sitting next to a media file, as
// relative URLs the player page can reference (e.g. "movie.en.srt?raw=1").
func (s *share) siblings(abs, name string) ([]subTrack, string) {
	dir := filepath.Dir(abs)
	base := strings.TrimSuffix(name, filepath.Ext(name))
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, ""
	}
	var tracks []subTrack
	poster := ""
	for _, de := range des {
		if de.IsDir() {
			continue
		}
		n := de.Name()
		if !strings.HasPrefix(n, base) || n == name {
			continue
		}
		ext := strings.ToLower(filepath.Ext(n))
		switch ext {
		case ".srt", ".vtt":
			label := strings.Trim(strings.TrimPrefix(strings.TrimSuffix(n, ext), base), ".-_ ")
			if label == "" {
				label = "subtitles"
			}
			def := ""
			if len(tracks) == 0 {
				def = "default"
			}
			tracks = append(tracks, subTrack{Src: url.PathEscape(n) + "?raw=1", Label: label, Default: def})
		case ".jpg", ".jpeg", ".png", ".webp":
			if poster == "" {
				poster = url.PathEscape(n) + "?raw=1"
			}
		}
	}
	return tracks, poster
}

// serveSubtitle serves a .vtt as-is or converts a .srt to WebVTT on the fly.
func (s *share) serveSubtitle(w *respRec, abs, ext string) {
	data, err := os.ReadFile(abs)
	if err != nil {
		http.Error(w, "404 not found", http.StatusNotFound)
		return
	}
	if ext == ".srt" {
		data = srtToVTT(data)
	}
	w.Header().Set("Content-Type", "text/vtt; charset=utf-8")
	w.Write(data)
}

// srtToVTT does a minimal SubRip→WebVTT conversion (header + comma→dot in
// timestamps); cue text passes through unchanged.
func srtToVTT(srt []byte) []byte {
	text := strings.ReplaceAll(string(srt), "\r\n", "\n")
	var b strings.Builder
	b.WriteString("WEBVTT\n\n")
	tsRe := regexp.MustCompile(`(\d\d:\d\d:\d\d),(\d\d\d)`)
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "-->") {
			line = tsRe.ReplaceAllString(line, "$1.$2")
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

func (s *share) countDownload() {
	n := s.dl.Add(1)
	s.updateState()
	if max := s.maxDL.Load(); max > 0 && n >= max {
		s.trigger(fmt.Sprintf("max downloads reached (%d)", n))
	}
}

// probeAlert notifies about invalid/unauthorized requests (with the caller's
// IP and the attempted URL), throttled so scanners can't notification-bomb.
func (s *share) probeAlert(who, method, path string, status int) {
	if s.cfg.NoNotify {
		return
	}
	s.probeMu.Lock()
	s.probeHeld++
	if time.Since(s.lastProbe) < 10*time.Second {
		s.probeMu.Unlock()
		return
	}
	held := s.probeHeld
	s.probeHeld = 0
	s.lastProbe = time.Now()
	s.probeMu.Unlock()

	msg := fmt.Sprintf("%s %s → %d from %s", method, path, status, who)
	if held > 1 {
		msg += fmt.Sprintf(" (+%d more in 10s)", held-1)
	}
	go notify("tshare — invalid access attempt", msg)
}

// ---------------------------------------------------------------------------
// zip streaming

func (s *share) handleZip(w *respRec, r *http.Request, dirRel string) {
	if r.Method != http.MethodGet {
		http.Error(w, "405", http.StatusMethodNotAllowed)
		return
	}
	if s.mode == "file" || s.mode == "inbox" {
		http.NotFound(w, r)
		return
	}
	type tgt struct{ prefix, abs string }
	var targets []tgt
	var zipName string

	if s.mode == "multi" && dirRel == "" {
		zipName = "tshare"
		for _, e := range s.roots {
			targets = append(targets, tgt{e.Name, e.Abs})
		}
	} else {
		abs, isDir, ok := s.resolve(dirRel)
		if !ok || !isDir {
			http.NotFound(w, r)
			return
		}
		zipName = filepath.Base(abs)
		targets = append(targets, tgt{zipName, abs})
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		mime.FormatMediaType("attachment", map[string]string{"filename": zipName + ".zip"}))
	zw := zip.NewWriter(w)
	okAll := true
	for _, t := range targets {
		fi, err := os.Stat(t.abs)
		if err != nil {
			okAll = false
			continue
		}
		if !fi.IsDir() {
			if err := zipAdd(zw, t.prefix, t.abs, fi); err != nil {
				okAll = false
			}
			continue
		}
		root := t.abs
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if p != root && strings.HasPrefix(d.Name(), ".") { // skip hidden
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Mode()&fs.ModeSymlink != 0 { // don't follow symlinks out
				return nil
			}
			relP, err := filepath.Rel(root, p)
			if err != nil {
				return nil
			}
			return zipAdd(zw, t.prefix+"/"+filepath.ToSlash(relP), p, info)
		})
		if err != nil {
			okAll = false
		}
	}
	if err := zw.Close(); err != nil {
		okAll = false
	}
	if r.Method == http.MethodGet && w.status == http.StatusOK && okAll {
		s.countDownload()
	}
}

func zipAdd(zw *zip.Writer, name, abs string, fi fs.FileInfo) error {
	hdr := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: fi.ModTime()}
	zf, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	f, err := os.Open(abs)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(zf, f)
	return err
}

// ---------------------------------------------------------------------------
// uploads

func (s *share) handleUpload(w *respRec, r *http.Request, dirRel string) {
	if s.upDir == "" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "405 use POST (multipart/form-data)", http.StatusMethodNotAllowed)
		return
	}
	destDir := s.upDir
	if s.mode == "dir" && dirRel != "" {
		abs, isDir, ok := s.resolve(dirRel)
		if !ok || !isDir {
			http.NotFound(w, r)
			return
		}
		destDir = abs
	}
	// disk guardrail: refuse when free space on the destination is below the
	// threshold (blackhole writes nothing, so it's exempt).
	if !s.blackhole && s.minFree > 0 {
		if free, err := diskFree(destDir); err == nil && free < s.minFree {
			http.Error(w, fmt.Sprintf("507 insufficient storage: %s free, need %s",
				humanSize(free), humanSize(s.minFree)), http.StatusInsufficientStorage)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.maxUp)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "400 expected multipart/form-data: "+err.Error(), http.StatusBadRequest)
		return
	}
	var saved []string
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "400 upload error: "+err.Error(), http.StatusBadRequest)
			return
		}
		name := sanitizeName(part.FileName())
		if name == "" {
			part.Close()
			continue
		}
		if s.blackhole { // -i: read and discard; nothing is written to disk
			n, err := io.Copy(io.Discard, part)
			part.Close()
			if err != nil {
				http.Error(w, "400 upload interrupted or too large: "+err.Error(), http.StatusBadRequest)
				return
			}
			saved = append(saved, fmt.Sprintf("%s (%s, discarded)", name, humanSize(n)))
			s.upCount.Add(1)
			continue
		}
		if s.encKey != nil { // #10: store encrypted, with a .enc suffix
			name += ".enc"
		}
		dst, fname, err := createUnique(destDir, name)
		if err != nil {
			part.Close()
			http.Error(w, "500 cannot save: "+err.Error(), http.StatusInternalServerError)
			return
		}
		var sink io.Writer = dst
		var enc io.WriteCloser
		if s.encKey != nil {
			if enc, err = encWriter(dst, s.encKey); err != nil {
				dst.Close()
				part.Close()
				http.Error(w, "500 cannot encrypt: "+err.Error(), http.StatusInternalServerError)
				return
			}
			sink = enc
		}
		_, err = io.Copy(sink, part)
		if enc != nil {
			if cerr := enc.Close(); err == nil {
				err = cerr
			}
		}
		dst.Close()
		part.Close()
		if err != nil {
			os.Remove(filepath.Join(destDir, fname))
			http.Error(w, "400 upload interrupted or too large: "+err.Error(), http.StatusBadRequest)
			return
		}
		saved = append(saved, fname)
		s.upCount.Add(1)
	}
	s.updateState()
	dstLabel := destDir
	if s.blackhole {
		dstLabel = "blackhole (discarded)"
	}
	if !s.cfg.Quiet {
		log.Printf("⇡ received %d file(s) → %s: %s", len(saved), dstLabel, strings.Join(saved, ", "))
	}
	if len(saved) > 0 && !s.cfg.NoNotify {
		go notify("tshare", fmt.Sprintf("received %d file(s): %s",
			len(saved), strings.Join(saved, ", ")))
	}
	w.Header().Set("Content-Type", "application/json")
	resp, _ := json.Marshal(map[string]any{"ok": true, "saved": saved})
	w.Write(resp)
}

func sanitizeName(n string) string {
	n = strings.ReplaceAll(n, "\\", "/")
	n = path.Base(n)
	if n == "/" || n == "." || n == ".." {
		return ""
	}
	var b strings.Builder
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	for strings.HasPrefix(out, "__") { // never collide with __upload/__zip endpoints
		out = out[1:]
	}
	return out
}

func createUnique(dir, name string) (*os.File, string, error) {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	try := name
	for i := 1; i < 1000; i++ {
		f, err := os.OpenFile(filepath.Join(dir, try), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil {
			return f, try, nil
		}
		if !os.IsExist(err) {
			return nil, "", err
		}
		try = fmt.Sprintf("%s (%d)%s", base, i, ext)
	}
	return nil, "", errors.New("too many name collisions")
}

// ---------------------------------------------------------------------------
// HTML pages

const pageCSS = `
:root { --bg:#ffffff; --fg:#1a1a2e; --mut:#777788; --line:#e8e8ef; --acc:#4f63ff; --card:#f6f6fa; }
@media (prefers-color-scheme: dark) {
 :root { --bg:#101018; --fg:#ececf4; --mut:#9a9aac; --line:#26263a; --acc:#7d8cff; --card:#181826; }
}
* { box-sizing:border-box; margin:0; }
body { background:var(--bg); color:var(--fg); font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width:780px; margin:0 auto; padding:28px 18px 60px; }
h1 { font-size:18px; font-weight:650; margin-bottom:4px; }
.crumbs { color:var(--mut); font-size:13px; margin-bottom:18px; }
.crumbs a { color:var(--acc); text-decoration:none; }
table { width:100%; border-collapse:collapse; }
td { padding:9px 8px; border-bottom:1px solid var(--line); }
td.sz, td.tm { color:var(--mut); font-size:13px; white-space:nowrap; text-align:right; }
a.f { color:var(--fg); text-decoration:none; }
a.f:hover { color:var(--acc); }
.dir { font-weight:600; }
td.dl { width:30px; text-align:center; }
td.dl a { color:var(--acc); text-decoration:none; font-size:15px; }
.bar { display:flex; gap:10px; margin:14px 0 20px; flex-wrap:wrap; }
.btn { background:var(--acc); color:#fff; border:none; border-radius:8px; padding:8px 14px; font-size:14px; text-decoration:none; cursor:pointer; }
.btn.sec { background:var(--card); color:var(--fg); border:1px solid var(--line); }
.drop { border:2px dashed var(--line); border-radius:12px; padding:34px; text-align:center; color:var(--mut); margin-top:18px; }
.drop.on { border-color:var(--acc); color:var(--acc); }
.done { color:var(--acc); font-size:13px; margin-top:10px; white-space:pre-line; }
.foot { color:var(--mut); font-size:12px; margin-top:34px; }
.abuse { color:var(--mut); font-size:11px; margin-top:6px; opacity:.75; }
.abuse a { color:inherit; }
.lb { position:fixed; inset:0; background:rgba(0,0,0,.92); display:none; align-items:center; justify-content:center; z-index:50; }
.lb.on { display:flex; }
.lb img { max-width:94vw; max-height:90vh; border-radius:8px; }
.lb .x { position:fixed; top:14px; right:18px; color:#fff; font-size:26px; cursor:pointer; }
.lb .nav { position:fixed; top:50%; transform:translateY(-50%); color:#fff; font-size:40px; cursor:pointer; padding:0 18px; user-select:none; opacity:.7; }
.lb .prev { left:4px; } .lb .next { right:4px; }
`

const uploadJS = `
function wire(box, input, status){
 function send(files){
  if(!files.length) return;
  var fd = new FormData();
  for (var i=0;i<files.length;i++) fd.append('f', files[i]);
  var xhr = new XMLHttpRequest();
  xhr.open('POST', document.body.dataset.upload || '__upload');
  xhr.upload.onprogress = function(e){
   if (e.lengthComputable) status.textContent = 'uploading… ' + Math.round(100*e.loaded/e.total) + '%';
  };
  xhr.onload = function(){
   if (xhr.status === 200) {
    var r = JSON.parse(xhr.responseText);
    status.textContent = 'received: ' + r.saved.join(', ');
    if (document.body.dataset.reload === '1') setTimeout(function(){ location.reload(); }, 700);
   } else status.textContent = 'failed: ' + xhr.responseText;
  };
  xhr.onerror = function(){ status.textContent = 'network error'; };
  status.textContent = 'uploading… 0%';
  xhr.send(fd);
 }
 box.addEventListener('dragover', function(e){ e.preventDefault(); box.classList.add('on'); });
 box.addEventListener('dragleave', function(){ box.classList.remove('on'); });
 box.addEventListener('drop', function(e){ e.preventDefault(); box.classList.remove('on'); send(e.dataTransfer.files); });
 box.addEventListener('click', function(){ input.click(); });
 input.addEventListener('change', function(){ send(input.files); });
}
wire(document.getElementById('drop'), document.getElementById('file'), document.getElementById('status'));
`

// galleryJS turns image rows into a swipeable lightbox (#31).
const galleryJS = `
(function(){
 var imgs = [].slice.call(document.querySelectorAll('a.img'));
 if(!imgs.length) return;
 var lb=document.getElementById('lb'), el=document.getElementById('lbimg'), idx=0;
 function show(i){ idx=(i+imgs.length)%imgs.length; el.src=imgs[idx].getAttribute('data-full'); lb.classList.add('on'); }
 function hide(){ lb.classList.remove('on'); el.src=''; }
 imgs.forEach(function(a,i){ a.addEventListener('click', function(e){ e.preventDefault(); show(i); }); });
 lb.querySelector('.x').addEventListener('click', hide);
 lb.querySelector('.prev').addEventListener('click', function(e){ e.stopPropagation(); show(idx-1); });
 lb.querySelector('.next').addEventListener('click', function(e){ e.stopPropagation(); show(idx+1); });
 lb.addEventListener('click', function(e){ if(e.target===lb) hide(); });
 document.addEventListener('keydown', function(e){ if(!lb.classList.contains('on'))return;
  if(e.key==='Escape')hide(); else if(e.key==='ArrowRight')show(idx+1); else if(e.key==='ArrowLeft')show(idx-1); });
})();
`

var dirTmpl = template.Must(template.New("dir").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>{{.Title}}</title>
<style>` + pageCSS + `</style></head>
<body data-reload="1" data-upload="{{.UploadURL}}">
<h1>📁 {{.Title}}</h1>
<div class="crumbs">{{range .Crumbs}}<a href="{{.Href}}">{{.Name}}</a> / {{end}}</div>
<div class="bar">
 <a class="btn" href="{{.ZipHref}}">⬇ download all (.zip)</a>
 {{if .AllowUp}}<button class="btn sec" onclick="document.getElementById('file').click()">⇡ upload here</button>{{end}}
</div>
<table>
{{range .Entries}}<tr>
 <td><a class="f {{if .IsDir}}dir{{end}}{{if .Img}} img{{end}}" href="{{.Href}}"{{if .Img}} data-full="{{.Href}}?raw=1"{{end}}>{{.Icon}} {{.Name}}</a></td>
 <td class="dl">{{if .DlHref}}<a href="{{.DlHref}}" title="download">⬇</a>{{end}}</td>
 <td class="sz">{{.Size}}</td><td class="tm">{{.Mod}}</td>
</tr>{{end}}
{{if not .Entries}}<tr><td colspan="4" style="color:var(--mut)">empty folder</td></tr>{{end}}
</table>
{{if .AllowUp}}
<div class="drop" id="drop">drop files here or click to upload</div>
<input type="file" id="file" multiple style="display:none">
<div class="done" id="status"></div>
<script>` + uploadJS + `</script>
{{end}}
{{if .Gallery}}
<div class="lb" id="lb"><span class="x">✕</span><span class="nav prev">‹</span><img id="lbimg" src=""><span class="nav next">›</span></div>
<script>` + galleryJS + `</script>
{{end}}
<div class="foot">shared with tshare · link is private — don't repost it</div>{{.Abuse}}
</body></html>`))

var inboxTmpl = template.Must(template.New("inbox").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>send files</title>
<style>` + pageCSS + `</style></head>
<body data-upload="{{.UploadURL}}">
<h1>⇡ Send files</h1>
<div class="crumbs">files go straight to the owner of this link</div>
<div class="drop" id="drop">drop files here or click to choose</div>
<input type="file" id="file" multiple style="display:none">
<div class="done" id="status"></div>
<noscript><form method="post" action="{{.UploadURL}}" enctype="multipart/form-data" style="margin-top:16px">
<input type="file" name="f" multiple> <button class="btn" type="submit">upload</button></form></noscript>
<script>` + uploadJS + `</script>
<div class="foot">powered by tshare · link is private — don't repost it</div>{{.Abuse}}
</body></html>`))

// mediaTmpl is a minimal, iOS-friendly player page. The media element streams
// from ?raw=1 (Range-served), playsinline keeps iOS from forcing an odd
// fullscreen frame, and the viewport/CSS make it fill the screen responsively.
var mediaTmpl = template.Must(template.New("media").Parse(`<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><title>{{.Name}}</title>
<style>
:root{color-scheme:dark light}
*{margin:0;box-sizing:border-box}
html,body{height:100%}
body{background:#000;color:#ececf4;font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
 display:flex;flex-direction:column;min-height:100%}
.stage{flex:1;display:flex;align-items:center;justify-content:center;padding:env(safe-area-inset-top) 12px 12px;overflow:auto}
video,img{max-width:100%;max-height:82vh;width:auto;height:auto;border-radius:10px;background:#000;display:block}
video{width:100%}
audio{width:min(680px,92vw)}
.bar{display:flex;gap:14px;align-items:center;justify-content:center;flex-wrap:wrap;
 padding:12px 14px calc(12px + env(safe-area-inset-bottom));border-top:1px solid #23232f;background:#101018}
.bar .nm{color:#9a9aac;max-width:60vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar a{color:#7d8cff;text-decoration:none;font-weight:600}
.abuse{color:#6a6a7c;font-size:11px;text-align:center;padding:0 12px calc(10px + env(safe-area-inset-bottom));opacity:.8}
.abuse a{color:inherit}
</style></head>
<body>
<div class="stage">
{{if eq .Kind "video"}}
 <video controls playsinline webkit-playsinline preload="metadata" x-webkit-airplay="allow"{{if .Poster}} poster="{{.Poster}}"{{end}}>
  <source src="?raw=1"{{if .Type}} type="{{.Type}}"{{end}}>
  {{range .Tracks}}<track kind="subtitles" src="{{.Src}}" label="{{.Label}}"{{if .Default}} default{{end}}>
  {{end}}your browser can't play this video — <a href="?dl=1">download it</a>.
 </video>
{{else if eq .Kind "audio"}}
 <audio controls preload="metadata">
  <source src="?raw=1"{{if .Type}} type="{{.Type}}"{{end}}>
  your browser can't play this audio — <a href="?dl=1">download it</a>.
 </audio>
{{else}}
 <img src="?raw=1" alt="{{.Name}}">
{{end}}
</div>
<div class="bar"><span class="nm">{{.Name}}</span><a href="?dl=1">⬇ download</a></div>
{{.Abuse}}
</body></html>`))

type crumb struct{ Name, Href string }
type entryView struct {
	Name, Href, DlHref, Size, Mod, Icon string
	IsDir                               bool
	Img                                 bool // image → eligible for the lightbox
}

func entryIcon(name string, isDir bool) string {
	if isDir {
		return "📁"
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".heic", ".svg", ".tif", ".tiff", ".ico":
		return "🖼"
	case ".mp4", ".webm", ".mov", ".m4v", ".mkv", ".avi":
		return "🎬"
	case ".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac":
		return "🎵"
	default:
		return "📄"
	}
}

// isMedia: types browsers can view/play natively → default to inline.
// (.svg is deliberately excluded: it can carry scripts, so it downloads.)
func isMedia(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".ico", ".tif", ".tiff",
		".mp4", ".webm", ".mov", ".m4v", ".mkv",
		".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac":
		return true
	}
	return false
}

func (s *share) renderDir(w *respRec, rel, abs, urlBase string) {
	if w.status != 0 { // already redirected
		return
	}
	// absolute URLs (include the token) — Tailscale strips the mount prefix,
	// so relative links against the browser's URL are unreliable.
	base := urlBase + "/"
	cur := base
	if rel != "" {
		cur += escPath(rel) + "/"
	}
	var entries []entryView
	if s.mode == "multi" && rel == "" {
		for _, e := range s.roots {
			ev := entryView{Name: e.Name, IsDir: e.IsDir, Icon: entryIcon(e.Name, e.IsDir), Img: !e.IsDir && isImageName(e.Name)}
			if e.IsDir {
				ev.Href = cur + url.PathEscape(e.Name) + "/"
				ev.Size = "—"
			} else {
				ev.Href = cur + url.PathEscape(e.Name)
				ev.DlHref = ev.Href + "?dl=1"
				ev.Size = humanSize(e.Size)
			}
			if fi, err := os.Stat(e.Abs); err == nil {
				ev.Mod = fi.ModTime().Format("2006-01-02 15:04")
			}
			entries = append(entries, ev)
		}
	} else {
		des, err := os.ReadDir(abs)
		if err != nil {
			http.Error(w, "500 cannot list folder", http.StatusInternalServerError)
			return
		}
		for _, de := range des {
			name := de.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			ev := entryView{Name: name, IsDir: de.IsDir(), Icon: entryIcon(name, de.IsDir()), Img: !de.IsDir() && isImageName(name)}
			if de.IsDir() {
				ev.Href = cur + url.PathEscape(name) + "/"
				ev.Size = "—"
			} else {
				ev.Href = cur + url.PathEscape(name)
				ev.DlHref = ev.Href + "?dl=1"
				if fi, err := de.Info(); err == nil {
					ev.Size = humanSize(fi.Size())
				}
			}
			if fi, err := de.Info(); err == nil {
				ev.Mod = fi.ModTime().Format("2006-01-02 15:04")
			}
			entries = append(entries, ev)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})

	title := "shared files"
	if s.mode == "dir" {
		title = filepath.Base(s.roots[0].Abs)
	}
	var crumbs []crumb
	crumbs = append(crumbs, crumb{Name: title, Href: base})
	if rel != "" {
		parts := strings.Split(rel, "/")
		for i, p := range parts {
			crumbs = append(crumbs, crumb{Name: p,
				Href: base + escPath(strings.Join(parts[:i+1], "/")) + "/"})
		}
		title = parts[len(parts)-1]
	}

	hasImg := false
	for _, e := range entries {
		if e.Img {
			hasImg = true
			break
		}
	}
	data := map[string]any{
		"Title": title, "Crumbs": crumbs, "Entries": entries,
		"AllowUp": s.upDir != "" && s.mode == "dir",
		"ZipHref": cur + "__zip", "UploadURL": cur + "__upload",
		"Gallery": hasImg && !s.cfg.NoGallery,
		"Abuse":   s.abuseHTML(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dirTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

func (s *share) renderInbox(w *respRec, urlBase string) {
	if w.status != 0 {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]any{"UploadURL": urlBase + "/__upload", "Abuse": s.abuseHTML()}
	if err := inboxTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

// ---------------------------------------------------------------------------
// tailscale integration

type tsInfo struct {
	BackendState string
	Self         struct{ DNSName string }
	CertDomains  []string
}

func tsBin(c *config) (string, error) {
	if c.TSBin != "" {
		return c.TSBin, nil
	}
	if env := os.Getenv("TAILSCALE"); env != "" {
		return env, nil
	}
	if p, err := exec.LookPath("tailscale"); err == nil {
		return p, nil
	}
	if runtime.GOOS == "darwin" {
		mac := "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
		if _, err := os.Stat(mac); err == nil {
			return mac, nil
		}
	}
	return "", errors.New("tailscale CLI not found (install Tailscale, or pass --tailscale-bin)")
}

func tsStatus(c *config) (*tsInfo, error) {
	bin, err := tsBin(c)
	if err != nil {
		return nil, err
	}
	out, err := exec.Command(bin, "status", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("`tailscale status` failed: %v", err)
	}
	var info tsInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, err
	}
	if info.BackendState != "Running" {
		return &info, fmt.Errorf("tailscale is %q (run `tailscale up`)", info.BackendState)
	}
	return &info, nil
}

func tsMount(c *config, mount string, port int) (string, error) {
	bin, err := tsBin(c)
	if err != nil {
		return "", err
	}
	args := []string{verb(c), "--bg",
		"--https=" + strconv.Itoa(c.HTTPSPort),
		"--set-path=/" + mount,
		"http://127.0.0.1:" + strconv.Itoa(port)}
	out, err := exec.Command(bin, args...).CombinedOutput()
	return string(out), err
}

func tsUnmount(c *config, mount string) {
	bin, err := tsBin(c)
	if err != nil {
		return
	}
	args := []string{verb(c),
		"--https=" + strconv.Itoa(c.HTTPSPort),
		"--set-path=/" + mount, "off"}
	exec.Command(bin, args...).CombinedOutput()
}

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
	return stateRec{
		ID: s.id, PID: os.Getpid(), Token: s.token, Mode: s.mode,
		URL: s.prettyURL(), Target: target, Tailnet: s.cfg.Tailnet, Local: s.cfg.Local,
		HTTPSPort: s.cfg.HTTPSPort, Port: port, Password: s.getPassword() != "",
		MaxDL: s.maxDL.Load(), Downloads: s.dl.Load(), Uploads: s.upCount.Load(),
		Created: s.createdAt, Expires: s.getExpires(),
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
			fmt.Println(rec.URL)
		} else if s.cfg.JSON {
			fmt.Println(string(b))
		} else {
			fmt.Printf("\n  ✓ sharing in background  (id %s, pid %d)\n", rec.ID, pid)
			fmt.Printf("  link     %s\n", rec.URL)
			if !rec.Expires.IsZero() {
				fmt.Printf("  expires  %s (use -e never to keep)\n", rec.Expires.Format("Jan 2 15:04"))
			}
			fmt.Printf("  log      %s\n", filepath.Join(logDir, s.id+".log"))
			fmt.Printf("  stop     tshare rm %s\n\n", rec.ID)
		}
		linkExtras(s.cfg, rec.URL)
		return nil
	}
	return errors.New("timed out waiting for background share (check tshare ls / logs)")
}

// ---------------------------------------------------------------------------
// subcommands

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

func cmdLs(args []string) {
	recs := loadStates()
	for _, a := range args {
		if a == "--json" || a == "-json" {
			b, _ := json.MarshalIndent(recs, "", "  ")
			fmt.Println(string(b))
			return
		}
	}
	if len(recs) == 0 {
		fmt.Println("no shares. start one: tshare <path>")
		return
	}
	fmt.Printf("\n  %-8s %-6s %-6s %-5s %-9s %s\n", "ID", "MODE", "STATE", "DL", "EXPIRES", "URL")
	defer fmt.Println("\n  stop: tshare rm <id> · change: tshare set <id> -p pw -e 3d -n 9 · stats: tshare info <id>")
	for _, r := range recs {
		state := "live"
		if !pidAlive(r.PID) {
			state = "dead"
		}
		exp := "never"
		if !r.Expires.IsZero() {
			if time.Now().After(r.Expires) {
				exp = "expired"
			} else {
				exp = humanDur(time.Until(r.Expires))
			}
		}
		dl := strconv.FormatInt(r.Downloads, 10)
		if r.MaxDL > 0 {
			dl += "/" + strconv.FormatInt(r.MaxDL, 10)
		}
		fmt.Printf("  %-8s %-6s %-6s %-5s %-9s %s\n", r.ID, r.Mode, state, dl, exp, r.URL)
		fmt.Printf("  %-8s → %s\n", "", r.Target)
	}
}

func cmdRm(args []string) {
	all := false
	var ids []string
	for _, a := range args {
		if a == "--all" || a == "-a" || a == "all" {
			all = true
		} else {
			ids = append(ids, a)
		}
	}
	recs := loadStates()
	if len(recs) == 0 {
		fmt.Println("nothing to stop")
		return
	}
	match := func(r stateRec) bool {
		if all {
			return true
		}
		for _, id := range ids {
			if r.ID == id || strings.HasPrefix(r.ID, id) {
				return true
			}
		}
		return false
	}
	n := 0
	for _, r := range recs {
		if !match(r) {
			continue
		}
		n++
		if pidAlive(r.PID) {
			syscall.Kill(r.PID, syscall.SIGTERM)
			for i := 0; i < 30 && pidAlive(r.PID); i++ {
				time.Sleep(100 * time.Millisecond)
			}
			if pidAlive(r.PID) {
				syscall.Kill(r.PID, syscall.SIGKILL)
			}
		}
		// belt & braces: remove funnel mount + state even if process is gone
		if !r.Local {
			c := &config{Tailnet: r.Tailnet, HTTPSPort: r.HTTPSPort}
			tsUnmount(c, r.Token)
		}
		os.Remove(stateFile(r.ID))
		fmt.Printf("  ✓ stopped %s (%s)\n", r.ID, r.URL)
	}
	if n == 0 {
		fmt.Println("no matching share id — see: tshare ls")
	}
}

// cmdPanic is the big red button: kill every share NOW (SIGKILL, no graceful
// drain), tear down every funnel mount, and wipe all local state — share
// records, resume/persist records and control sockets — so no token survives.
func cmdPanic() {
	recs := loadStates()
	for _, r := range recs {
		if pidAlive(r.PID) {
			syscall.Kill(r.PID, syscall.SIGKILL) // no waiting — this is a panic
		}
		if !r.Local {
			tsUnmount(&config{Tailnet: r.Tailnet, HTTPSPort: r.HTTPSPort}, r.Token)
		}
		os.Remove(stateFile(r.ID))
		os.Remove(persistFile(r.ID))
		os.Remove(filepath.Join(ctlDir(), r.ID+".sock"))
	}
	// belt & braces: clear any orphaned records/sockets left by crashed shares.
	wipeDir := func(dir string) {
		if des, err := os.ReadDir(dir); err == nil {
			for _, de := range des {
				os.Remove(filepath.Join(dir, de.Name()))
			}
		}
	}
	wipeDir(stateDir())
	wipeDir(persistDir())
	wipeDir(ctlDir())
	fmt.Printf("  ✓ panic: killed %d share(s), unmounted funnels, wiped all tokens & state\n", len(recs))
}

// cmdExtend pushes out a running share's expiry. With no duration it DOUBLES
// the time remaining (the default); pass a duration to add that instead.
// A share with no expiry ("never") is already immortal, so it's a no-op.
func cmdExtend(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: tshare extend <id> [duration]   (no duration = double the time left)")
		return
	}
	id := resolveID(args[0])
	form := url.Values{}
	if len(args) >= 2 && strings.TrimSpace(args[1]) != "" {
		form.Set("extend", args[1]) // add this much
	} else {
		form.Set("extend", "double") // default: double remaining
	}
	client, err := ctlClient(id)
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	resp, err := client.Post("http://tshare/set", "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("tshare: %s", strings.TrimSpace(string(b)))
	}
	var out struct {
		Changed []string `json:"changed"`
	}
	if json.Unmarshal(b, &out) == nil && len(out.Changed) > 0 {
		for _, ch := range out.Changed {
			fmt.Printf("  ✓ %s\n", ch)
		}
	} else {
		fmt.Println(strings.TrimSpace(string(b)))
	}
}

func cmdDoctor() {
	okm := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}
	c := &config{HTTPSPort: 443}
	fmt.Println("\n  tshare doctor")

	bin, err := tsBin(c)
	fmt.Printf("  %s tailscale CLI: %s\n", okm(err == nil), orErr(bin, err))
	if err != nil {
		fmt.Println("    → install from https://tailscale.com/download")
		return
	}
	if out, err := exec.Command(bin, "version").Output(); err == nil {
		fmt.Printf("  ✓ version: %s\n", strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]))
	}

	info, err := tsStatus(c)
	fmt.Printf("  %s backend running: %s\n", okm(err == nil), orErr("yes", err))
	if info != nil {
		dns := strings.TrimSuffix(info.Self.DNSName, ".")
		fmt.Printf("  %s MagicDNS name: %s\n", okm(dns != ""), orErr(dns, nil))
		fmt.Printf("  %s HTTPS certs: %v\n", okm(len(info.CertDomains) > 0), info.CertDomains)
		if dns == "" {
			fmt.Println("    → enable MagicDNS + HTTPS: https://tailscale.com/kb/1153/enabling-https")
		}
	}

	out, ferr := exec.Command(bin, "funnel", "status").CombinedOutput()
	fmt.Printf("  %s funnel available: ", okm(ferr == nil))
	if ferr == nil {
		fmt.Println("yes")
	} else {
		fmt.Printf("no\n    %s\n    → enable the funnel attribute: https://tailscale.com/kb/1223/funnel\n",
			strings.TrimSpace(string(out)))
	}

	yb, yerr := ytBin()
	fmt.Printf("  %s yt-dlp (optional): %s\n", okm(yerr == nil), orErr(yb, yerr))
	if yerr != nil {
		fmt.Println("    → for URL sharing: brew install yt-dlp (or pipx install yt-dlp)")
	}
	if _, err := exec.LookPath("qrencode"); err != nil {
		fmt.Println("  ✗ qrencode (optional): not found → brew install qrencode for QR codes")
	} else {
		fmt.Println("  ✓ qrencode (optional): yes")
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		fmt.Println("  ✗ ffmpeg (optional): not found → brew install ffmpeg for --transcode/--hevc")
	} else {
		fmt.Println("  ✓ ffmpeg (optional): yes")
	}
	if inv := copypartyInvocation(&config{}); inv != nil {
		fmt.Printf("  ✓ copyparty (optional): %s\n", strings.Join(inv, " "))
	} else {
		fmt.Println("  ✗ copyparty (optional): not found → pip install copyparty for richer folders")
	}

	fmt.Println("\n  all good? share something: tshare <path>  ·  tshare <video-url>")
}

func orErr(ok string, err error) string {
	if err != nil {
		return err.Error()
	}
	return ok
}

// ---------------------------------------------------------------------------
// control socket: change options on a running share (tshare set / info)

func ctlDir() string {
	d := filepath.Join(filepath.Dir(stateDir()), "ctl")
	os.MkdirAll(d, 0o700)
	return d
}

func (s *share) ctlServe() {
	s.ctlPath = filepath.Join(ctlDir(), s.id+".sock")
	os.Remove(s.ctlPath)
	ln, err := net.Listen("unix", s.ctlPath)
	if err != nil {
		if !s.cfg.Quiet {
			log.Printf("warn: control socket unavailable: %v", err)
		}
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		s.stateMu.Lock()
		rec := s.stateRec(s.lastPort)
		s.stateMu.Unlock()
		resp := struct {
			stateRec
			Uptime      string `json:"uptime"`
			ViewersNow  int64  `json:"viewers_now"`
			BytesServed int64  `json:"bytes_served"`
		}{rec, time.Since(s.createdAt).Round(time.Second).String(), s.viewers.Load(), s.bytesServed.Load()}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.MarshalIndent(resp, "", "  ")
		w.Write(b)
	})
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var changed []string
		if r.Form.Has("password") {
			s.mu.Lock()
			s.password = r.Form.Get("password")
			s.mu.Unlock()
			if r.Form.Get("password") == "" {
				changed = append(changed, "password cleared")
			} else {
				changed = append(changed, "password updated")
			}
		}
		if r.Form.Has("expires") {
			d, err := parseDuration(r.Form.Get("expires"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			if d == 0 {
				s.expiresAt = time.Time{}
				changed = append(changed, "expiry removed")
			} else {
				s.expiresAt = time.Now().Add(d)
				changed = append(changed, "expires "+s.expiresAt.Format("Jan 2 15:04"))
			}
			s.mu.Unlock()
		}
		if r.Form.Has("extend") {
			note, err := s.doExtend(r.Form.Get("extend"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			changed = append(changed, note)
		}
		if r.Form.Has("max") {
			n, err := strconv.ParseInt(r.Form.Get("max"), 10, 64)
			if err != nil || n < 0 {
				http.Error(w, "max must be a non-negative integer", http.StatusBadRequest)
				return
			}
			s.maxDL.Store(n)
			changed = append(changed, fmt.Sprintf("max downloads → %d", n))
		}
		s.updateState() // after releasing s.mu (lock order: stateMu → mu)
		if !s.cfg.Quiet && len(changed) > 0 {
			log.Printf("⚙ settings changed: %s", strings.Join(changed, "; "))
		}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(map[string]any{"ok": true, "changed": changed})
		w.Write(b)
	})
	go http.Serve(ln, mux)
}

// resolveID expands a (possibly prefix) id to a known share id.
func resolveID(id string) string {
	for _, r := range loadStates() {
		if r.ID == id || strings.HasPrefix(r.ID, id) {
			return r.ID
		}
	}
	return id
}

func ctlClient(id string) (*http.Client, error) {
	sock := filepath.Join(ctlDir(), id+".sock")
	if _, err := os.Stat(sock); err != nil {
		return nil, fmt.Errorf("share %q has no control socket here — is it running? (tshare ls)", id)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}, nil
}

func cmdSet(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: tshare set <id> [-p password] [-e duration|never] [-n max-downloads]")
		return
	}
	id := resolveID(args[0])
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	pw := fs.String("p", "", "")
	fs.StringVar(pw, "password", "", "")
	exp := fs.String("e", "", "")
	fs.StringVar(exp, "expires", "", "")
	max := fs.String("n", "", "")
	fs.StringVar(max, "max", "", "")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: tshare set <id> [-p password] [-e duration|never] [-n max-downloads]")
	}
	fs.Parse(args[1:])
	form := url.Values{}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "p", "password":
			form.Set("password", *pw)
		case "e", "expires":
			form.Set("expires", *exp)
		case "n", "max":
			form.Set("max", *max)
		}
	})
	if len(form) == 0 {
		fmt.Println("nothing to change — pass -p, -e and/or -n")
		return
	}
	client, err := ctlClient(id)
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	resp, err := client.Post("http://tshare/set", "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("tshare: %s", strings.TrimSpace(string(b)))
	}
	var out struct {
		Changed []string `json:"changed"`
	}
	if json.Unmarshal(b, &out) == nil && len(out.Changed) > 0 {
		for _, ch := range out.Changed {
			fmt.Printf("  ✓ %s\n", ch)
		}
	} else {
		fmt.Println(strings.TrimSpace(string(b)))
	}
}

func cmdInfo(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: tshare info <id>")
		return
	}
	id := resolveID(args[0])
	client, err := ctlClient(id)
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	resp, err := client.Get("http://tshare/info")
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(strings.TrimSpace(string(b)))
}

// ---------------------------------------------------------------------------
// stdin shares (pipes)

// sniffExt guesses a file extension from leading magic bytes.
func sniffExt(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG")):
		return ".png"
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		return ".jpg"
	case bytes.HasPrefix(b, []byte("GIF8")):
		return ".gif"
	case len(b) >= 12 && string(b[4:8]) == "ftyp":
		return ".mp4"
	case bytes.HasPrefix(b, []byte{0x1A, 0x45, 0xDF, 0xA3}):
		return ".webm" // EBML: webm/mkv
	case bytes.HasPrefix(b, []byte("ID3")):
		return ".mp3"
	case bytes.HasPrefix(b, []byte("OggS")):
		return ".ogg"
	case len(b) >= 12 && string(b[0:4]) == "RIFF" && string(b[8:12]) == "WAVE":
		return ".wav"
	case len(b) >= 12 && string(b[0:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return ".webp"
	case bytes.HasPrefix(b, []byte("fLaC")):
		return ".flac"
	case bytes.HasPrefix(b, []byte("%PDF")):
		return ".pdf"
	case bytes.HasPrefix(b, []byte("PK\x03\x04")):
		return ".zip"
	case bytes.HasPrefix(b, []byte{0x1F, 0x8B}):
		return ".gz"
	}
	return ".bin"
}

// bufferStdin spools stdin to a temp file; the share starts at EOF, i.e. when
// the producing command (yt-dlp, tar, …) has finished.
func bufferStdin(c *config, id string) (string, string, error) {
	tmpDir := filepath.Join(filepath.Dir(stateDir()), "tmp")
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		return "", "", err
	}
	fmt.Fprintln(os.Stderr, "  ⇣ reading stdin… (share starts at EOF)")
	head := make([]byte, 16)
	n, err := io.ReadFull(os.Stdin, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", "", err
	}
	name := c.FileName
	if name == "" {
		name = "shared-" + id + sniffExt(head[:n])
	}
	name = sanitizeName(name)
	if name == "" {
		name = "shared-" + id + ".bin"
	}
	p := filepath.Join(tmpDir, id+"-"+name)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", err
	}
	if _, err := f.Write(head[:n]); err != nil {
		f.Close()
		os.Remove(p)
		return "", "", err
	}
	if _, err := io.Copy(f, os.Stdin); err != nil {
		f.Close()
		os.Remove(p)
		return "", "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(p)
		return "", "", err
	}
	return p, name, nil
}

// ---------------------------------------------------------------------------
// yt-dlp integration: download a URL, then share the resulting file(s)

func looksLikeURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// isatty reports whether f is an interactive terminal (a character device).
func isatty(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func ytBin() (string, error) {
	for _, name := range []string{"yt-dlp", "youtube-dl"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", errors.New("yt-dlp not found — install it (brew install yt-dlp, or pipx install yt-dlp), then retry")
}

// shellSplit does a minimal POSIX-ish split honoring single/double quotes,
// enough for passing extra flags through --yt-args.
func shellSplit(s string) []string {
	var out []string
	var cur strings.Builder
	inS, inD, has := false, false, false
	flush := func() {
		if has {
			out = append(out, cur.String())
			cur.Reset()
			has = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inS:
			if c == '\'' {
				inS = false
			} else {
				cur.WriteByte(c)
			}
			has = true
		case inD:
			if c == '"' {
				inD = false
			} else if c == '\\' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			} else {
				cur.WriteByte(c)
			}
			has = true
		case c == '\'':
			inS, has = true, true
		case c == '"':
			inD, has = true, true
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	flush()
	return out
}

// ytFetch runs yt-dlp into a fresh temp dir and returns the produced media
// file(s). The share begins only after yt-dlp exits cleanly (download done).
// Defaults to an iOS-friendly MP4 (H.264/AAC); overridable via --yt-format,
// --yt-audio, --yt-args.
func ytFetch(c *config, id string) (roots []rootEnt, dir string, err error) {
	bin, err := ytBin()
	if err != nil {
		return nil, "", err
	}
	base := filepath.Join(filepath.Dir(stateDir()), "tmp")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, "", err
	}
	dir = filepath.Join(base, "yt-"+id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}

	args := ytArgs(c, dir)

	fmt.Fprintf(os.Stderr, "  ▶ yt-dlp: fetching %s …\n", c.Paths[0])
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stderr // progress/info → our stderr, keep stdout (URL) clean
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	if err := cmd.Run(); err != nil {
		return nil, dir, fmt.Errorf("yt-dlp failed: %v", err)
	}

	roots, err = collectMedia(dir)
	if err != nil {
		return nil, dir, err
	}
	if len(roots) == 0 {
		return nil, dir, errors.New("yt-dlp produced no media file (check the URL / format)")
	}
	total := int64(0)
	for _, r := range roots {
		total += r.Size
	}
	fmt.Fprintf(os.Stderr, "  ✓ downloaded %d file(s), %s\n", len(roots), humanSize(total))
	return roots, dir, nil
}

// ytArgs builds the yt-dlp argv shared by the blocking fetch and the async
// (link-up-front) download: output template, format selection, and the URL.
func ytArgs(c *config, dir string) []string {
	args := []string{
		// yt-dlp uses an in-place \r progress bar on a TTY (one line). We pass
		// it our real stderr, so it stays a single updating line. When stderr
		// is NOT a tty (piped/logged), force a quiet console to avoid spamming
		// thousands of progress lines into the log.
		"-o", filepath.Join(dir, "%(title).180B [%(id)s].%(ext)s"),
		"--no-mtime",
	}
	if !isatty(os.Stderr) {
		args = append(args, "--no-progress")
	}
	if c.Playlist {
		args = append(args, "--yes-playlist")
	} else {
		args = append(args, "--no-playlist")
	}
	switch {
	case c.YtAudio:
		// smart audio: grab the best audio-only stream (no wasted video
		// download), prefer a native M4A/AAC so it plays everywhere incl. iOS,
		// then tag it with metadata + embedded cover art. Prefer itag 139
		// (small m4a/AAC, one stream → one clean 0→100), falling back to any
		// m4a / best audio if it isn't offered.
		args = append(args,
			"-f", "139/ba[ext=m4a]/ba/bestaudio/best",
			"-x", "--audio-format", "m4a", "--audio-quality", "0",
			"--embed-metadata", "--embed-thumbnail",
		)
	case c.YtFormat != "":
		args = append(args, "-f", c.YtFormat)
	default:
		// prefer already-MP4/M4A streams, then remux to a clean MP4 container
		// so iOS Safari can stream and seek it.
		args = append(args, "-S", "ext:mp4:m4a", "--remux-video", "mp4")
	}
	if c.YtArgs != "" {
		args = append(args, shellSplit(c.YtArgs)...)
	}
	args = append(args, "--", c.Paths[0])
	return args
}

// dropArg returns args with every occurrence of flag removed (no value pairs).
func dropArg(args []string, flag string) []string {
	out := args[:0:0]
	for _, a := range args {
		if a != flag {
			out = append(out, a)
		}
	}
	return out
}

// ytMakeDir creates (and returns) the per-share temp dir yt-dlp downloads into.
func ytMakeDir(id string) (string, error) {
	base := filepath.Join(filepath.Dir(stateDir()), "tmp")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", err
	}
	dir := filepath.Join(base, "yt-"+id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// ytFilename does a cheap metadata-only pass to learn the eventual file name, so
// the share can print a real link + QR before the download finishes. The final
// container differs from the source ext for our defaults (remux→mp4, audio→m4a),
// so the extension is forced to match; a custom --yt-format keeps yt-dlp's own
// guess. Either way file mode serves roots[0] for any sub-path, so the link
// still resolves even if this name turns out slightly off.
func ytFilename(c *config, dir string) (string, error) {
	bin, err := ytBin()
	if err != nil {
		return "", err
	}
	args := append([]string{"--no-playlist", "--print", "filename",
		"-o", filepath.Join(dir, "%(title).180B [%(id)s].%(ext)s")}, "--", c.Paths[0])
	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		return "", fmt.Errorf("yt-dlp could not read %s: %v", c.Paths[0], err)
	}
	name := filepath.Base(strings.TrimSpace(string(out)))
	if name == "" || name == "." {
		return "", errors.New("yt-dlp returned no filename (check the URL)")
	}
	switch {
	case c.YtAudio:
		name = strings.TrimSuffix(name, filepath.Ext(name)) + ".m4a"
	case c.YtFormat == "":
		name = strings.TrimSuffix(name, filepath.Ext(name)) + ".mp4"
	}
	return name, nil
}

var ytPctRe = regexp.MustCompile(`(\d+(?:\.\d+)?)%`)
var ytFmtCountRe = regexp.MustCompile(`Downloading (\d+) format\(s\)`)

// ytDownload runs the real (single-file) yt-dlp download in the background while
// the share is already live, parsing progress into s.ytPend and swapping the
// placeholder root for the finished file when done.
func ytDownload(c *config, s *share) {
	bin, err := ytBin()
	if err != nil {
		s.ytPend.finish(err)
		return
	}
	dir := s.tmpDir
	// We always need yt-dlp's progress to drive the web percentage, so force
	// --newline (one update per line, easy to scan) and drop the --no-progress
	// that ytArgs adds for non-TTY stderr. We still avoid log spam by only
	// echoing lines to stderr when it's an interactive terminal.
	args := append([]string{"--newline"}, dropArg(ytArgs(c, dir), "--no-progress")...)
	echo := isatty(os.Stderr)
	fmt.Fprintf(os.Stderr, "  ▶ yt-dlp: fetching %s …\n", c.Paths[0])
	cmd := exec.Command(bin, args...)
	cmd.Stdin = nil
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		total := 1      // download passes yt-dlp will make (e.g. video + audio)
		completed := 0  // passes fully finished before the current one
		lastRaw := -1.0 // last per-stream % seen (to detect the next stream)
		overall := 0.0  // monotonic 0→100 across all passes (web + terminal)
		inProg := false // terminal: currently sitting on an in-place progress line
		for sc.Scan() {
			line := sc.Text()
			// "Downloading 2 format(s): 137+140" → expect 2 passes; collapse them
			// into a single 0→100 so the bar doesn't restart per stream.
			if m := ytFmtCountRe.FindStringSubmatch(line); m != nil {
				if n, e := strconv.Atoi(m[1]); e == nil && n > 0 {
					total = n
				}
			}
			prog := false
			if m := ytPctRe.FindStringSubmatch(line); m != nil {
				if raw, e := strconv.ParseFloat(m[1], 64); e == nil {
					prog = true
					if raw+5 < lastRaw { // big drop → yt-dlp moved to the next stream
						completed++
					}
					lastRaw = raw
					if completed >= total {
						total = completed + 1 // we under-counted; keep ≤100
					}
					if o := (float64(completed)*100 + raw) / float64(total); o > overall {
						overall = o // never goes backwards: one smooth 0→100
					}
					s.ytPend.set(overall)
				}
			}
			if !echo {
				continue
			}
			if prog {
				// rewrite a single line in place rather than scrolling
				fmt.Fprintf(os.Stderr, "\r\033[K  ⬇ downloading… %.0f%%", overall)
				inProg = true
			} else {
				if inProg {
					fmt.Fprintln(os.Stderr) // finish the in-place line first
					inProg = false
				}
				fmt.Fprintln(os.Stderr, line)
			}
		}
		if echo && inProg {
			fmt.Fprintln(os.Stderr)
		}
	}()
	runErr := cmd.Run()
	pw.Close()
	if runErr != nil {
		s.ytPend.finish(fmt.Errorf("yt-dlp failed: %v", runErr))
		return
	}
	roots, err := collectMedia(dir)
	if err == nil && len(roots) == 0 {
		err = errors.New("yt-dlp produced no media file (check the URL / format)")
	}
	if err != nil {
		s.ytPend.finish(err)
		return
	}
	// Swap the placeholder root for the real file *before* marking done; the
	// handler reads `done` under ytPend.mu before touching s.roots, which gives
	// the happens-before so it never sees a half-updated root.
	s.roots[0] = roots[0]
	s.tmpRoot = roots[0].Abs
	s.ytPend.set(100)
	s.ytPend.finish(nil)
	if !c.Quiet {
		fmt.Fprintf(os.Stderr, "  ✓ downloaded %s (%s)\n", roots[0].Name, humanSize(roots[0].Size))
	}
}

// collectMedia lists finished output files in dir, skipping sidecars and
// partials, sorted by name.
func collectMedia(dir string) ([]rootEnt, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	skip := map[string]bool{
		".part": true, ".ytdl": true, ".json": true, ".description": true,
		".vtt": true, ".srt": true, ".lrc": true, ".temp": true,
	}
	var out []rootEnt
	for _, de := range des {
		if de.IsDir() || strings.HasPrefix(de.Name(), ".") {
			continue
		}
		ext := strings.ToLower(filepath.Ext(de.Name()))
		if skip[ext] || strings.HasSuffix(de.Name(), ".info.json") {
			continue
		}
		fi, err := de.Info()
		if err != nil || fi.Size() == 0 {
			continue
		}
		out = append(out, rootEnt{
			Name: de.Name(), Abs: filepath.Join(dir, de.Name()), IsDir: false, Size: fi.Size(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// stripYtFlags removes the input-producing yt-dlp flags (and their values) from
// a re-exec argv, so a backgrounded child serves the already-downloaded file
// instead of downloading again.
func stripYtFlags(args []string) []string {
	valFlags := map[string]bool{"--yt-format": true, "--yt-args": true}
	boolFlags := map[string]bool{
		"-Y": true, "--yt-dlp": true, "-a": true, "--yt-audio": true, "--playlist": true,
	}
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		key := a
		if eq := strings.IndexByte(a, '='); eq >= 0 {
			key = a[:eq] // handle --yt-format=foo
		}
		if boolFlags[key] {
			continue
		}
		if valFlags[key] {
			if strings.IndexByte(a, '=') < 0 {
				i++ // also skip the separate value token
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// ---------------------------------------------------------------------------
// copyparty folder engine (reverse-proxied behind tshare)

// useCopyparty decides whether this share's folder traffic should be handled by
// copyparty. Only single-folder browse/upload/inbox shares qualify; multi-path
// and encrypted-inbox shares stay native.
func (s *share) useCopyparty() bool {
	c := s.cfg
	if c.NoCopyparty {
		return false
	}
	if s.blackhole { // sentinel upDir, no real folder — must stay native/discard
		return false
	}
	if s.encKey != nil { // native inbox does the at-rest encryption
		return false
	}
	if s.mode != "dir" && s.mode != "inbox" {
		return false
	}
	if c.Copyparty {
		return true // forced
	}
	// auto: use copyparty when it's installed
	return copypartyInvocation(c) != nil
}

// copypartyInvocation returns the command prefix that launches copyparty, or
// nil if it can't be found.
func pythonBin() string {
	for _, p := range []string{"python3", "python"} {
		if abs, err := exec.LookPath(p); err == nil {
			return abs
		}
	}
	return ""
}

func copypartyInvocation(c *config) []string {
	explicit := c.CopypartyBin
	if explicit == "" {
		explicit = os.Getenv("TSHARE_COPYPARTY")
	}
	if explicit != "" {
		if strings.HasSuffix(explicit, ".py") || strings.HasSuffix(explicit, ".pyz") {
			if py := pythonBin(); py != "" {
				return []string{py, explicit}
			}
		}
		return []string{explicit}
	}
	// 1) a `copyparty` launcher on PATH
	if p, err := exec.LookPath("copyparty"); err == nil {
		return []string{p}
	}
	// 2) common install dirs that GUI-launched apps often miss on PATH
	home, _ := os.UserHomeDir()
	for _, d := range []string{
		filepath.Join(home, ".local", "bin", "copyparty"),
		"/opt/homebrew/bin/copyparty", "/usr/local/bin/copyparty",
		filepath.Join(home, "bin", "copyparty"),
	} {
		if fi, err := os.Stat(d); err == nil && !fi.IsDir() {
			return []string{d}
		}
	}
	// 3) python -m copyparty (installed as a module in the same interpreter)
	if py := pythonBin(); py != "" {
		if exec.Command(py, "-c", "import copyparty").Run() == nil {
			return []string{py, "-m", "copyparty"}
		}
	}
	return nil
}

// copyparty streaming buffers. 4 MiB is copyparty's largest documented-safe
// --iobuf; the socket write size stays a notch below to avoid edge cases.
const (
	cpIObuf  = "4194304" // 4 MiB
	cpSockSz = "2097152" // 2 MiB
)

// startCopyparty launches copyparty on a loopback port serving the share's
// folder at the volume location /<token>, then builds the reverse proxy.
func startCopyparty(s *share) error {
	c := s.cfg
	inv := copypartyInvocation(c)
	if inv == nil {
		return errors.New("copyparty not found (pip install copyparty, or set --copyparty-bin)")
	}
	dir := s.roots[0].Abs
	if s.mode == "inbox" {
		dir = s.upDir
	}
	// permission: read-only browse, rw when uploads allowed, write-only inbox
	perm := "r"
	switch {
	case s.mode == "inbox":
		perm = "w" // upload-only drop box (no listing/download)
	case s.upDir != "": // --allow-upload
		perm = "rw"
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	s.cpPort = port

	// copyparty sits behind tshare under the secret /<token> subpath. --rp-loc
	// tells it that base path so every URL it emits (including its /.cpr static
	// assets like baguettebox.js) is prefixed with /<token> and therefore stays
	// inside the Tailscale funnel mount instead of escaping to the root. The
	// volume is mounted at copyparty's webroot; rp-loc supplies the prefix, and
	// tshare always forwards the full /<token>/… path (see ServeHTTP).
	args := append([]string{}, inv[1:]...)
	args = append(args,
		"-i", "127.0.0.1",
		"-p", strconv.Itoa(port),
		"-q",                    // quiet
		"--rp-loc", "/"+s.token, // we sit under the secret /<token> subpath
		// Maximize the I/O buffer copyparty uses when streaming (incl. ffmpeg
		// opus transcodes) — 4 MiB is copyparty's documented safe ceiling;
		// going higher risks per-connection memory blowup / OOM crashes.
		"--iobuf", cpIObuf,
		"--s-wr-sz", cpSockSz, // larger socket write chunks → smoother audio
		"-v", dir+"::"+perm, // src : (webroot) : perm (anonymous)
	)
	if c.CopypartyArgs != "" {
		// user args come last so they can override our buffer defaults
		args = append(args, shellSplit(c.CopypartyArgs)...)
	}
	cmd := exec.Command(inv[0], args...)
	// capture stderr so a bad-flag / crash-on-start explains itself; still echo
	// it live unless we're in quiet mode.
	var errbuf bytes.Buffer
	if c.Quiet {
		cmd.Stderr = &errbuf
	} else {
		cmd.Stderr = io.MultiWriter(os.Stderr, &errbuf)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} // own process group
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not launch %s: %w", strings.Join(inv, " "), err)
	}
	s.cpCmd = cmd

	// watch for early exit (e.g. an unrecognized flag) while we poll the port
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	addr := "127.0.0.1:" + strconv.Itoa(port)
	deadline := time.After(15 * time.Second)
	ready := false
	for !ready {
		select {
		case werr := <-exited:
			tail := strings.TrimSpace(errbuf.String())
			if len(tail) > 400 {
				tail = "…" + tail[len(tail)-400:]
			}
			return fmt.Errorf("copyparty exited at startup (%v)\n%s", werr, tail)
		case <-deadline:
			cmd.Process.Kill()
			s.cpCmd = nil
			return errors.New("copyparty did not start listening in time")
		default:
			if conn, derr := net.DialTimeout("tcp", addr, 300*time.Millisecond); derr == nil {
				conn.Close()
				ready = true
			} else {
				time.Sleep(150 * time.Millisecond)
			}
		}
	}

	target := &url.URL{Scheme: "http", Host: addr}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = 250 * time.Millisecond // stream downloads
	proxy.BufferPool = proxyBufPool             // reuse 64 KiB buffers (less GC)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, e error) {
		if !c.Quiet {
			log.Printf("  copyparty proxy error: %v", e)
		}
		http.Error(w, "502 folder backend unavailable", http.StatusBadGateway)
	}
	s.cpProxy = proxy
	return nil
}

// bufPool is an httputil.BufferPool backed by a sync.Pool of 64 KiB slices, so
// the reverse proxy reuses transfer buffers instead of allocating per request.
type bufPool struct{ p sync.Pool }

func (b *bufPool) Get() []byte  { return b.p.Get().([]byte) }
func (b *bufPool) Put(x []byte) { b.p.Put(x) }

var proxyBufPool = &bufPool{p: sync.Pool{New: func() any { return make([]byte, 64<<10) }}}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

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

func setupServer(c *config, s *share) error {
	u, err := url.Parse(c.Paths[0])
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("-s needs an http(s) URL, e.g. tshare -s http://localhost:8000")
	}
	s.mode = "server"
	s.srvURL = c.Paths[0]
	s.roots = []rootEnt{{Name: u.Host, Abs: c.Paths[0]}} // placeholder for shared code
	base := strings.TrimSuffix(u.Path, "/")

	s.srvProxy = &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = u.Scheme
			req.URL.Host = u.Host
			// Present the upstream's own host so dev servers' host-check
			// (webpack/vite "Invalid Host header") accepts the request.
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
			http.Error(w, "502 upstream not reachable — is your server running at "+s.srvURL+" ?", http.StatusBadGateway)
		},
	}
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

// ---------------------------------------------------------------------------
// #51 generic URL fetch (wget-style)

func fetchURL(c *config, id string) ([]rootEnt, string, error) {
	src := c.Paths[0]
	base := filepath.Join(filepath.Dir(stateDir()), "tmp")
	if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, "", err
	}
	fmt.Fprintf(os.Stderr, "  ▶ fetching %s …\n", src)
	req, err := http.NewRequest(http.MethodGet, src, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "tshare/"+version)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("fetch failed: HTTP %s", resp.Status)
	}
	name := c.FileName
	if name == "" {
		name = fetchName(resp, src)
	}
	if name = sanitizeName(name); name == "" {
		name = "download-" + id
	}
	p := filepath.Join(base, id+"-"+name)
	f, err := os.Create(p)
	if err != nil {
		return nil, "", err
	}
	n, err := io.Copy(f, resp.Body)
	f.Close()
	if err != nil {
		return nil, p, err
	}
	fmt.Fprintf(os.Stderr, "  ✓ fetched %s\n", humanSize(n))
	return []rootEnt{{Name: name, Abs: p, Size: n}}, p, nil
}

func fetchName(resp *http.Response, src string) string {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			if fn := params["filename"]; fn != "" {
				return fn
			}
		}
	}
	if u, err := url.Parse(src); err == nil {
		if b := path.Base(u.Path); b != "" && b != "/" && b != "." {
			return b
		}
	}
	return "download"
}

// ---------------------------------------------------------------------------
// #10 at-rest encryption for received files (chunked AES-256-GCM)
//
// File format: magic "TSE1" | 16-byte salt | repeated [4-byte BE chunk len |
// ciphertext+tag]. Each chunk is sealed with a nonce of random8 || counter,
// where random8 is derived once from the key+salt; the trailing counter
// guarantees per-chunk uniqueness. Key = scrypt-free SHA-256(passphrase|salt)
// — simple and dependency-free; for a generated key it's already 256-bit.

const encMagic = "TSE1"
const encChunk = 1 << 20 // 1 MiB plaintext chunks

func resolveEncKey(c *config) ([]byte, error) {
	if c.encKeyHex != "" {
		k, err := hex.DecodeString(c.encKeyHex)
		if err != nil || len(k) != 32 {
			return nil, errors.New("bad inherited encryption key")
		}
		return k, nil
	}
	if c.Password != "" { // derive from the share password
		sum := sha256.Sum256([]byte("tshare-enc:" + c.Password))
		return sum[:], nil
	}
	// generate and show once — the user needs it to decrypt later
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	c.encKeyHex = hex.EncodeToString(k)
	fmt.Fprintf(os.Stderr, "  🔐 inbox encryption key (save this — needed to decrypt):\n     %s\n", c.encKeyHex)
	return k, nil
}

func encWriter(dst io.Writer, key []byte) (io.WriteCloser, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	gcm, base, err := encGCM(key, salt)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(dst, encMagic); err != nil {
		return nil, err
	}
	if _, err := dst.Write(salt); err != nil {
		return nil, err
	}
	return &chunkEncWriter{dst: dst, gcm: gcm, base: base}, nil
}

func encGCM(key, salt []byte) (cipher.AEAD, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	// derive an 8-byte nonce prefix from key+salt; counter fills the rest
	h := sha256.Sum256(append(append([]byte("nonce"), key...), salt...))
	base := make([]byte, gcm.NonceSize())
	copy(base, h[:8])
	return gcm, base, nil
}

type chunkEncWriter struct {
	dst     io.Writer
	gcm     cipher.AEAD
	base    []byte
	counter uint64
	buf     []byte
}

func (w *chunkEncWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for len(w.buf) >= encChunk {
		if err := w.seal(w.buf[:encChunk]); err != nil {
			return 0, err
		}
		w.buf = w.buf[encChunk:]
	}
	return len(p), nil
}

func (w *chunkEncWriter) seal(plain []byte) error {
	nonce := make([]byte, len(w.base))
	copy(nonce, w.base)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] = byte(w.counter >> (8 * i))
	}
	w.counter++
	ct := w.gcm.Seal(nil, nonce, plain, nil)
	var lenb [4]byte
	lenb[0], lenb[1], lenb[2], lenb[3] = byte(len(ct)>>24), byte(len(ct)>>16), byte(len(ct)>>8), byte(len(ct))
	if _, err := w.dst.Write(lenb[:]); err != nil {
		return err
	}
	_, err := w.dst.Write(ct)
	return err
}

func (w *chunkEncWriter) Close() error {
	if len(w.buf) > 0 {
		return w.seal(w.buf)
	}
	return nil
}

func decryptFile(in io.Reader, out io.Writer, key []byte) error {
	magic := make([]byte, 4)
	if _, err := io.ReadFull(in, magic); err != nil || string(magic) != encMagic {
		return errors.New("not a tshare-encrypted file")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(in, salt); err != nil {
		return err
	}
	gcm, base, err := encGCM(key, salt)
	if err != nil {
		return err
	}
	var counter uint64
	var lenb [4]byte
	for {
		_, err := io.ReadFull(in, lenb[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		clen := int(lenb[0])<<24 | int(lenb[1])<<16 | int(lenb[2])<<8 | int(lenb[3])
		ct := make([]byte, clen)
		if _, err := io.ReadFull(in, ct); err != nil {
			return err
		}
		nonce := make([]byte, len(base))
		copy(nonce, base)
		for i := 0; i < 8; i++ {
			nonce[len(nonce)-1-i] = byte(counter >> (8 * i))
		}
		counter++
		plain, err := gcm.Open(nil, nonce, ct, nil)
		if err != nil {
			return errors.New("decryption failed (wrong key or corrupt file)")
		}
		if _, err := out.Write(plain); err != nil {
			return err
		}
	}
}

func cmdDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	pw := fs.String("p", "", "passphrase")
	fs.StringVar(pw, "password", "", "")
	keyHex := fs.String("key", "", "raw 64-hex-char key")
	outDir := fs.String("o", ".", "output directory")
	fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Println("usage: tshare decrypt [-p pass | -key HEX] [-o dir] <file.enc>...")
		return
	}
	var key []byte
	switch {
	case *keyHex != "":
		k, err := hex.DecodeString(*keyHex)
		if err != nil || len(k) != 32 {
			log.Fatal("tshare: -key must be 64 hex chars (32 bytes)")
		}
		key = k
	case *pw != "":
		sum := sha256.Sum256([]byte("tshare-enc:" + *pw))
		key = sum[:]
	default:
		log.Fatal("tshare: need -p <passphrase> or -key <hex>")
	}
	for _, in := range fs.Args() {
		f, err := os.Open(in)
		if err != nil {
			log.Printf("  ✗ %s: %v", in, err)
			continue
		}
		outName := strings.TrimSuffix(filepath.Base(in), ".enc")
		outPath := filepath.Join(*outDir, outName)
		of, err := os.Create(outPath)
		if err != nil {
			f.Close()
			log.Printf("  ✗ %s: %v", in, err)
			continue
		}
		err = decryptFile(f, of, key)
		f.Close()
		of.Close()
		if err != nil {
			os.Remove(outPath)
			log.Printf("  ✗ %s: %v", in, err)
			continue
		}
		fmt.Printf("  ✓ %s → %s\n", in, outPath)
	}
}

// ---------------------------------------------------------------------------
// media transforms (#33 EXIF strip, #35 transcode/HEVC, HEIF→JPEG)

func isImageName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".ico",
		".tif", ".tiff", ".heic", ".heif":
		return true
	}
	return false
}

func isVideoName(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".mp4", ".webm", ".mov", ".m4v", ".mkv", ".avi", ".wmv", ".flv", ".ts", ".mpg", ".mpeg":
		return true
	}
	return false
}

func cacheDir() string {
	d := filepath.Join(filepath.Dir(stateDir()), "cache")
	os.MkdirAll(d, 0o700)
	return d
}

// cachePath returns a stable cache file path for (abs,mtime,tag).
func cachePath(abs, tag, ext string) (string, bool) {
	fi, err := os.Stat(abs)
	if err != nil {
		return "", false
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d|%s", abs, fi.ModTime().UnixNano(), fi.Size(), tag)))
	p := filepath.Join(cacheDir(), hex.EncodeToString(h[:10])+ext)
	if cfi, err := os.Stat(p); err == nil && cfi.Size() > 0 {
		return p, true // cache hit
	}
	return p, false
}

// maybeTransform applies the configured media transforms to a file about to be
// served, returning the path to actually serve and the adjusted public name.
// Any failure falls back to the original file.
func (s *share) maybeTransform(abs, name string) (string, string) {
	c := s.cfg
	ext := strings.ToLower(filepath.Ext(name))

	// HEIC/HEIF → JPEG so browsers can display it
	if c.Heif && (ext == ".heic" || ext == ".heif") {
		out, hit := cachePath(abs, "heif-jpeg", ".jpg")
		if hit || convertHEIF(abs, out) == nil {
			return out, strings.TrimSuffix(name, filepath.Ext(name)) + ".jpg"
		}
	}
	// transcode video (optionally to hardware HEVC, optionally constant-quality)
	if c.Transcode && isVideoName(name) {
		codec := "h264"
		if c.Hevc {
			codec = "hevc"
		}
		cq := 0 // --265 selects constant-quality; plain --transcode keeps bitrate mode
		key := "transcode-" + codec
		if c.H265 {
			cq = c.CQ
			key = fmt.Sprintf("%s-cq%d", key, cq)
		}
		out, hit := cachePath(abs, key, ".mp4")
		if hit || transcodeVideo(abs, out, c.Hevc, cq) == nil {
			return out, strings.TrimSuffix(name, filepath.Ext(name)) + ".mp4"
		}
	}
	// strip EXIF/metadata from JPEGs
	if c.StripExif && (ext == ".jpg" || ext == ".jpeg") {
		out, hit := cachePath(abs, "noexif", ".jpg")
		if hit {
			return out, name
		}
		if err := stripJPEGMetadataFile(abs, out); err == nil {
			return out, name
		}
	}
	return abs, name
}

// convertHEIF turns a HEIC/HEIF into a JPEG using whatever tool is present.
func convertHEIF(in, out string) error {
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("sips"); err == nil {
			return exec.Command("sips", "-s", "format", "jpeg", in, "--out", out).Run()
		}
	}
	if p, err := exec.LookPath("heif-convert"); err == nil {
		return exec.Command(p, in, out).Run()
	}
	if p, err := exec.LookPath("magick"); err == nil {
		return exec.Command(p, in, out).Run()
	}
	if p, err := exec.LookPath("convert"); err == nil {
		return exec.Command(p, in, out).Run()
	}
	if p, err := exec.LookPath("ffmpeg"); err == nil {
		return exec.Command(p, "-y", "-i", in, out).Run()
	}
	return errors.New("no HEIC converter found (install libheif/imagemagick, or use macOS sips)")
}

// transcodeVideo re-encodes to an MP4 (H.264 or HEVC), preferring a
// hardware encoder for the platform and falling back to software.
//
// cq==0 keeps the historical average-bitrate behaviour. cq>0 selects a
// constant-quality mode (used by --265): each encoder's own quality knob is set
// so file size floats to hit a fixed perceptual quality (roughly CRF-like;
// higher cq ⇒ smaller/softer).
func transcodeVideo(in, out string, hevc bool, cq int) error {
	ff, err := exec.LookPath("ffmpeg")
	if err != nil {
		return errors.New("ffmpeg not found (brew install ffmpeg)")
	}
	vcodec, extra := pickVideoEncoder(hevc, cq)
	args := []string{"-y", "-i", in, "-c:v", vcodec}
	args = append(args, extra...)
	args = append(args, "-c:a", "aac", "-b:a", "160k", "-movflags", "+faststart", out)
	cmd := exec.Command(ff, args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err == nil {
		return nil
	}
	// fall back to software encoder if the hardware one failed
	sw := "libx264"
	tag := []string{}
	if hevc {
		sw = "libx265"
		tag = []string{"-tag:v", "hvc1"}
	}
	args = append([]string{"-y", "-i", in, "-c:v", sw}, tag...)
	if cq > 0 { // software encoders take CRF directly
		args = append(args, "-crf", strconv.Itoa(cq))
	}
	args = append(args, "-c:a", "aac", "-b:a", "160k", "-movflags", "+faststart", out)
	cmd = exec.Command(ff, args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// pickVideoEncoder chooses a hardware-accelerated encoder by platform. When
// cq>0 it returns that encoder's constant-quality flags instead of a target
// bitrate (VideoToolbox -q:v, NVENC constqp/-qp, or x26x -crf).
func pickVideoEncoder(hevc bool, cq int) (string, []string) {
	cqs := strconv.Itoa(cq)
	switch runtime.GOOS {
	case "darwin": // VideoToolbox; hvc1 tag makes HEVC playable in Safari/QuickTime
		if hevc {
			if cq > 0 {
				return "hevc_videotoolbox", []string{"-tag:v", "hvc1", "-q:v", cqs}
			}
			return "hevc_videotoolbox", []string{"-tag:v", "hvc1", "-b:v", "6M"}
		}
		if cq > 0 {
			return "h264_videotoolbox", []string{"-q:v", cqs}
		}
		return "h264_videotoolbox", []string{"-b:v", "6M"}
	case "linux": // try NVENC; ffmpeg falls back to software path on failure
		if hevc {
			if cq > 0 {
				return "hevc_nvenc", []string{"-tag:v", "hvc1", "-rc", "constqp", "-qp", cqs}
			}
			return "hevc_nvenc", []string{"-tag:v", "hvc1"}
		}
		if cq > 0 {
			return "h264_nvenc", []string{"-rc", "constqp", "-qp", cqs}
		}
		return "h264_nvenc", nil
	default:
		if hevc {
			if cq > 0 {
				return "libx265", []string{"-tag:v", "hvc1", "-crf", cqs}
			}
			return "libx265", []string{"-tag:v", "hvc1"}
		}
		if cq > 0 {
			return "libx264", []string{"-crf", cqs}
		}
		return "libx264", nil
	}
}

// stripJPEGMetadataFile copies a JPEG dropping APPn metadata (EXIF, XMP, IPTC)
// and comment segments — lossless, no re-encode, pure Go.
func stripJPEGMetadataFile(in, out string) error {
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	stripped, err := stripJPEGMetadata(data)
	if err != nil {
		return err
	}
	return os.WriteFile(out, stripped, 0o644)
}

func stripJPEGMetadata(d []byte) ([]byte, error) {
	if len(d) < 2 || d[0] != 0xFF || d[1] != 0xD8 {
		return nil, errors.New("not a JPEG")
	}
	out := []byte{0xFF, 0xD8}
	i := 2
	for i+1 < len(d) {
		if d[i] != 0xFF {
			return append(out, d[i:]...), nil // resync: copy the rest
		}
		marker := d[i+1]
		if marker == 0xD9 { // EOI
			out = append(out, d[i:]...)
			break
		}
		// start of scan → copy everything from here to the end
		if marker == 0xDA {
			out = append(out, d[i:]...)
			break
		}
		if i+3 >= len(d) {
			break
		}
		segLen := int(d[i+2])<<8 | int(d[i+3])
		if i+2+segLen > len(d) {
			break
		}
		drop := marker == 0xFE || (marker >= 0xE0 && marker <= 0xEF) // COM or APPn
		if !drop {
			out = append(out, d[i:i+2+segLen]...)
		}
		i += 2 + segLen
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// #49 progressive / live: serve a file while it is still being written

// ytPending tracks an in-progress default yt-dlp download so the share can go
// live (link + QR printed) up front while visitors are held with a percentage
// page until the file is ready.
type ytPending struct {
	mu      sync.Mutex
	percent float64
	done    bool
	err     error
}

func (p *ytPending) set(pct float64) { p.mu.Lock(); p.percent = pct; p.mu.Unlock() }

func (p *ytPending) finish(err error) {
	p.mu.Lock()
	p.done = true
	if p.err == nil {
		p.err = err
	}
	p.mu.Unlock()
}

func (p *ytPending) state() (pct float64, done bool, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.percent, p.done, p.err
}

type growing struct {
	path string
	mu   sync.Mutex
	cond *sync.Cond
	size int64
	done bool
	err  error
}

func newGrowing(id, name string) (*growing, error) {
	dir := filepath.Join(filepath.Dir(stateDir()), "tmp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "grow-"+id+"-"+name)
	f, err := os.Create(p)
	if err != nil {
		return nil, err
	}
	f.Close()
	g := &growing{path: p}
	g.cond = sync.NewCond(&g.mu)
	return g, nil
}

// fill streams the producer into the backing file, waking readers as it grows.
func (g *growing) fill(src io.ReadCloser, s *share) {
	defer src.Close()
	f, err := os.OpenFile(g.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		g.finish(err)
		return
	}
	defer f.Close()
	buf := make([]byte, 256<<10)
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := f.Write(buf[:n]); werr != nil {
				g.finish(werr)
				return
			}
			g.mu.Lock()
			g.size += int64(n)
			g.cond.Broadcast()
			g.mu.Unlock()
		}
		if rerr != nil {
			if rerr == io.EOF {
				rerr = nil
			}
			g.finish(rerr)
			if !s.cfg.Quiet {
				st, _ := os.Stat(g.path)
				if st != nil {
					log.Printf("  ✓ source complete (%s)", humanSize(st.Size()))
				}
			}
			return
		}
	}
}

func (g *growing) finish(err error) {
	g.mu.Lock()
	g.done = true
	if g.err == nil {
		g.err = err
	}
	g.cond.Broadcast()
	g.mu.Unlock()
}

func (g *growing) state() (size int64, done bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.size, g.done
}

// serve streams the growing file, blocking for more bytes until the producer
// finishes. Once complete, it serves normally (with Range/seek support).
func (g *growing) serve(w http.ResponseWriter, r *http.Request, name string, inline bool) {
	disp := "attachment"
	if inline {
		disp = "inline"
	}
	w.Header().Set("Content-Disposition", mime.FormatMediaType(disp, map[string]string{"filename": name}))
	if ct := mediaContentType(name); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if _, done := g.state(); done {
		f, err := os.Open(g.path)
		if err != nil {
			http.Error(w, "410 gone", http.StatusGone)
			return
		}
		defer f.Close()
		fi, _ := f.Stat()
		w.Header().Set("Accept-Ranges", "bytes")
		http.ServeContent(w, r, name, fi.ModTime(), f)
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	f, err := os.Open(g.path)
	if err != nil {
		http.Error(w, "500", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	flusher, _ := w.(http.Flusher)
	w.WriteHeader(http.StatusOK)
	buf := make([]byte, 256<<10)
	var off int64
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return // client went away
			}
			off += int64(n)
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr == io.EOF {
			g.mu.Lock()
			for g.size <= off && !g.done {
				g.cond.Wait()
			}
			finished := g.done && g.size <= off
			g.mu.Unlock()
			if finished {
				return
			}
			continue // file grew; next Read returns the new bytes
		}
		if rerr != nil {
			return
		}
	}
}

// setupProgressive wires a growing buffer fed by stdin or a yt-dlp stream.
func setupProgressive(c *config, s *share) error {
	src := c.Paths[0]
	name := c.FileName
	var producer io.ReadCloser
	switch {
	case src == "-":
		if name == "" {
			name = "stream-" + s.id
		}
		producer = os.Stdin
	case looksLikeURL(src):
		var err error
		if name == "" {
			name = "stream-" + s.id + ".mp4"
		}
		if producer, err = ytStream(c, src); err != nil {
			return err
		}
	default:
		return errors.New("--progressive/--live needs stdin (-) or a URL")
	}
	if name = sanitizeName(name); name == "" {
		name = "stream-" + s.id
	}
	g, err := newGrowing(s.id, name)
	if err != nil {
		return err
	}
	s.grow = g
	s.mode = "file"
	s.tmpFile = g.path
	s.roots = []rootEnt{{Name: name, Abs: g.path}}
	go g.fill(producer, s)
	if c.Live {
		fmt.Fprintln(os.Stderr, "  ⇣ live: streaming to viewers as bytes arrive…")
	} else {
		fmt.Fprintln(os.Stderr, "  ⇣ progressive: serving while it downloads…")
	}
	return nil
}

// ytStream starts yt-dlp writing to stdout for progressive/live serving.
func ytStream(c *config, urlStr string) (io.ReadCloser, error) {
	bin, err := ytBin()
	if err != nil {
		return nil, err
	}
	args := []string{"-o", "-", "--no-part", "--no-playlist"}
	if c.Live {
		args = append(args, "--live-from-start")
	}
	switch {
	case c.YtAudio:
		args = append(args, "-f", "ba/bestaudio/best")
	case c.YtFormat != "":
		args = append(args, "-f", c.YtFormat)
	}
	if c.YtArgs != "" {
		args = append(args, shellSplit(c.YtArgs)...)
	}
	args = append(args, "--", urlStr)
	cmd := exec.Command(bin, args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &cmdReader{ReadCloser: out, cmd: cmd}, nil
}

type cmdReader struct {
	io.ReadCloser
	cmd *exec.Cmd
}

func (c *cmdReader) Close() error {
	err := c.ReadCloser.Close()
	c.cmd.Wait()
	return err
}

// ---------------------------------------------------------------------------
// #64 self-signed TLS for LAN-only HTTPS

func selfSignedTLS(hosts []string) (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "tshare-local"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
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
	// strip daemon-internal flags; keep --persist so a resumed share re-persists
	var args []string
	skip := map[string]bool{"--__daemon": true, "--__id": true, "--__tmp": true, "--__tmpdir": true, "--__enckey": true}
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

// ---------------------------------------------------------------------------
// interactive: change options on a running foreground share by typing them

func (s *share) repl() {
	fmt.Fprintln(os.Stderr, "  ⌨  live controls — type options to change them, e.g.:")
	fmt.Fprintln(os.Stderr, "       -p secret   -e 2d   -n 5   --no-password   info   stop")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch line {
		case "":
			continue
		case "stop", "quit", "exit", "q":
			s.trigger("typed stop")
			return
		case "help", "?":
			fmt.Fprintln(os.Stderr, "  options: -p <pw> | --no-password | -e <dur|never> | -x [dur] | -n <N> | info | stop")
		case "info":
			fmt.Fprintf(os.Stderr, "  ↳ %d downloads · %d uploads · %d viewing · expires %s\n",
				s.dl.Load(), s.upCount.Load(), s.viewers.Load(), s.expiresLabel())
		case "-x", "x", "extend":
			s.replExtend("")
		default:
			if f := strings.Fields(line); len(f) == 2 && (f[0] == "-x" || f[0] == "x" || f[0] == "extend") {
				s.replExtend(f[1])
				continue
			}
			s.applyOptionLine(line)
		}
	}
}

// replExtend handles the live `-x [dur]` control: double the remaining time,
// or add an explicit duration.
func (s *share) replExtend(spec string) {
	note, err := s.doExtend(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ? %v\n", err)
		return
	}
	s.updateState()
	fmt.Fprintf(os.Stderr, "  ⚙ %s\n", note)
}

// abuseHTML returns the small-font takedown/abuse line for public share pages,
// or "" when no --abuse-contact is configured. The minimum needed for a public
// host to display a report/takedown path; kept deliberately unobtrusive.
func (s *share) abuseHTML() template.HTML {
	c := strings.TrimSpace(s.cfg.AbuseContact)
	if c == "" {
		return ""
	}
	inner := template.HTMLEscapeString(c)
	if strings.Contains(c, "@") && !strings.Contains(c, " ") {
		inner = `<a href="mailto:` + inner + `">` + inner + `</a>`
	} else if strings.HasPrefix(c, "http://") || strings.HasPrefix(c, "https://") {
		inner = `<a href="` + inner + `" rel="nofollow noreferrer">` + inner + `</a>`
	}
	return template.HTML(`<div class="abuse">Report abuse / request takedown: ` + inner + `</div>`)
}

func (s *share) expiresLabel() string {
	t := s.getExpires()
	if t.IsZero() {
		return "never"
	}
	return humanDur(time.Until(t))
}

// applyOptionLine parses a line of flags and applies them to the live share.
func (s *share) applyOptionLine(line string) {
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pw := fs.String("p", "\x00", "")
	fs.StringVar(pw, "password", "\x00", "")
	noPw := fs.Bool("no-password", false, "")
	exp := fs.String("e", "\x00", "")
	fs.StringVar(exp, "expires", "\x00", "")
	maxs := fs.String("n", "\x00", "")
	fs.StringVar(maxs, "max", "\x00", "")
	if err := fs.Parse(shellSplit(line)); err != nil {
		fmt.Fprintf(os.Stderr, "  ? %v (try: help)\n", err)
		return
	}
	var changed []string
	if *noPw {
		s.mu.Lock()
		s.password = ""
		s.mu.Unlock()
		changed = append(changed, "password cleared")
	} else if *pw != "\x00" {
		s.mu.Lock()
		s.password = *pw
		s.mu.Unlock()
		changed = append(changed, "password updated")
	}
	if *exp != "\x00" {
		d, err := parseDuration(*exp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ? bad duration %q\n", *exp)
			return
		}
		s.mu.Lock()
		if d == 0 {
			s.expiresAt = time.Time{}
		} else {
			s.expiresAt = time.Now().Add(d)
		}
		s.mu.Unlock()
		changed = append(changed, "expiry "+s.expiresLabel())
	}
	if *maxs != "\x00" {
		n, err := strconv.ParseInt(*maxs, 10, 64)
		if err != nil || n < 0 {
			fmt.Fprintln(os.Stderr, "  ? -n needs a non-negative integer")
			return
		}
		s.maxDL.Store(n)
		changed = append(changed, fmt.Sprintf("max-dl → %d", n))
	}
	if len(changed) == 0 {
		fmt.Fprintln(os.Stderr, "  ? nothing changed (try: help)")
		return
	}
	s.updateState()
	fmt.Fprintf(os.Stderr, "  ⚙ %s\n", strings.Join(changed, "; "))
}

// ---------------------------------------------------------------------------
// misc utils

func humanDur(d time.Duration) string {
	if d <= 0 {
		return "0m"
	}
	days := int64(d / (24 * time.Hour))
	h := int64((d % (24 * time.Hour)) / time.Hour)
	m := int64((d % time.Hour) / time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh", days, h)
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	default:
		return fmt.Sprintf("%dm", m)
	}
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// remoteIsLoopback reports whether a request's RemoteAddr is a loopback
// address — i.e. it was proxied in by the local tailscaled, not a direct peer.
func remoteIsLoopback(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func lanIP() string {
	conn, err := net.Dial("udp", "192.0.2.1:9") // no packets sent; just routes
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

func copyClipboard(text string) bool {
	var cands [][]string
	if runtime.GOOS == "darwin" {
		cands = [][]string{{"pbcopy"}}
	} else {
		cands = [][]string{{"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "-ib"}}
	}
	for _, cand := range cands {
		if _, err := exec.LookPath(cand[0]); err != nil {
			continue
		}
		cmd := exec.Command(cand[0], cand[1:]...)
		cmd.Stdin = strings.NewReader(text)
		if cmd.Run() == nil {
			return true
		}
	}
	return false
}

func qrencodeOK() bool {
	_, err := exec.LookPath("qrencode")
	return err == nil
}

// printQR writes to stderr so `tshare --quiet -q | pbcopy`-style pipes stay clean.
func printQR(link string) {
	cmd := exec.Command("qrencode", "-t", "ANSIUTF8", "-m", "2", link)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func openBrowser(link string) {
	bin := "xdg-open"
	if runtime.GOOS == "darwin" {
		bin = "open"
	}
	if _, err := exec.LookPath(bin); err == nil {
		exec.Command(bin, link).Start()
	}
}

// notify sends a desktop notification; silently a no-op when unsupported.
func notify(title, body string) {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("osascript"); err != nil {
			return
		}
		esc := func(s string) string {
			s = strings.ReplaceAll(s, `\`, `\\`)
			return strings.ReplaceAll(s, `"`, `\"`)
		}
		script := fmt.Sprintf(`display notification "%s" with title "%s"`, esc(body), esc(title))
		exec.Command("osascript", "-e", script).Run()
	default:
		if _, err := exec.LookPath("notify-send"); err != nil {
			return
		}
		exec.Command("notify-send", title, body).Run()
	}
}
