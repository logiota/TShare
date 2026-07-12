//go:build unix

package main

import (
	"archive/zip"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

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
	senderTab := s.senderReq(r) // --p2p local sender: free (loopback, not funnel egress)
	defer func() {
		// #13 byte cap: tally served bytes; stop at the 1.5× hard ceiling
		if s.maxBytes > 0 && rec.bytes > 0 && !senderTab {
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

	// optional password (HTTP Basic, any username). The --p2p sender tab
	// authenticates with its own per-share secret key instead (it is opened
	// locally and can't carry Basic-Auth creds through the auto-open).
	if want := s.getPassword(); want != "" && !s.senderReq(r) {
		_, pw, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pw), []byte(want)) != 1 {
			rec.Header().Set("WWW-Authenticate", `Basic realm="tshare"`)
			http.Error(rec, "401 password required", http.StatusUnauthorized)
			return
		}
	}

	rel := strings.Trim(path.Clean("/"+p), "/") // ""=root, no dot-dots

	// WebRTC signaling (--p2p / --call) + the local sender tab page
	if s.hub != nil && (rel == "__rtc" || strings.HasPrefix(rel, "__rtc/")) {
		s.handleRTC(rec, r, strings.TrimPrefix(strings.TrimPrefix(rel, "__rtc"), "/"))
		return
	}
	if s.senderKey != "" && rel == "__p2p/send" {
		s.renderP2PSend(rec, r)
		return
	}

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
	// content-types, scripts allowed). Owns all routing — no zip; __upload only
	// when --allow-upload opted in (e.g. GIGA-NET/1-L game signalling).
	if s.mode == "site" {
		if s.upDir != "" && (rel == "__upload" || strings.HasSuffix(rel, "/__upload")) {
			s.handleUpload(rec, r, strings.TrimSuffix(strings.TrimSuffix(rel, "__upload"), "/"))
			return
		}
		// --gamelink: hand the GIGA-NET/1-L page its ICE config so a funnel/tailnet
		// game can hole-punch across networks (STUN/TURN); -l stays pure LAN.
		if s.gameSid != "" && (rel == "__ice" || strings.HasSuffix(rel, "/__ice")) {
			s.handleGameIce(rec, r)
			return
		}
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
	if rel == "__report" || strings.HasSuffix(rel, "/__report") {
		s.handleReport(rec, r, who)
		return
	}

	// --hub control endpoints (some are POST → route before the GET-only guard).
	// __upload/__zip above already work for the hub; everything else here.
	if s.mode == "hub" {
		switch rel {
		case "", "__grab", "__jobs", "__list", "__rm", "__note",
			"manifest.webmanifest", "apple-touch-icon.png", "icon.png":
			ub := s.baseURL
			if !proxied && s.lanURL != "" {
				ub = s.lanURL
			}
			s.handleHub(rec, r, rel, ub)
			return
		}
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
	case "room":
		if rel != "" {
			http.NotFound(rec, r)
			return
		}
		if r.URL.Query().Get("go") == "1" { // deep-link straight into the call
			http.Redirect(rec, r, s.roomURL, http.StatusFound)
			return
		}
		s.renderRoom(rec)
	case "kuma":
		if rel != "" {
			http.NotFound(rec, r)
			return
		}
		if r.URL.Query().Get("go") == "1" { // straight to the dashboard
			http.Redirect(rec, r, s.kumaURL, http.StatusFound)
			return
		}
		s.renderKuma(rec)
	case "dashboard":
		if rel == "__shares" {
			s.dashJSON(rec)
			return
		}
		if rel != "" {
			http.NotFound(rec, r)
			return
		}
		s.renderDashboard(rec)
	case "call":
		if rel != "" {
			http.NotFound(rec, r)
			return
		}
		s.renderCall(rec)
	case "inbox":
		if rel != "" {
			http.NotFound(rec, r)
			return
		}
		s.renderInbox(rec, urlBase)
	case "hub":
		// root + endpoints handled above; here rel is a filename in the hub dir
		abs, isDir, ok := s.resolve(rel)
		if !ok || isDir {
			http.NotFound(rec, r)
			return
		}
		s.serveFile(rec, r, abs, path.Base("/"+rel))
	case "file":
		// --p2p: browser navigations get the direct-transfer page (P2P attempt
		// + standard-download fallback); ?dl=1 / ?raw=1 / curl get bytes as ever.
		if s.senderKey != "" && r.Method == http.MethodGet &&
			r.URL.Query().Get("dl") != "1" && r.URL.Query().Get("raw") != "1" &&
			strings.Contains(r.Header.Get("Accept"), "text/html") {
			s.renderP2PRecv(rec)
			return
		}
		s.serveFile(rec, r, s.roots[0].Abs, s.roots[0].Name)
	case "dir", "multi":
		// --p2p folder share (e.g. --rar volumes): the root becomes the
		// per-file direct-transfer page; every file stays reachable directly.
		if s.senderKey != "" && rel == "" && r.Method == http.MethodGet &&
			r.URL.Query().Get("dl") != "1" && r.URL.Query().Get("raw") != "1" &&
			strings.Contains(r.Header.Get("Accept"), "text/html") {
			s.renderP2PRecv(rec)
			return
		}
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
			if r.Method == http.MethodGet && w.status == http.StatusOK && !s.senderReq(r) {
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
	// so a seeking video player isn't counted as many downloads. The --p2p
	// sender tab reading the file over loopback isn't a download either.
	if r.Method == http.MethodGet && w.status == http.StatusOK && !s.senderReq(r) {
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

// handleReport is the always-available abuse channel behind the ⚑ report button
// on share pages — the minimal "report" affordance a public host is expected to
// offer. It needs zero config: it notifies the share's owner and shows the
// reporter a short confirmation, surfacing any --abuse-contact for escalation.
func (s *share) handleReport(w *respRec, r *http.Request, who string) {
	label := s.token
	if len(s.roots) > 0 && s.roots[0].Name != "" {
		label = s.roots[0].Name
	}
	s.reportAlert(who, label)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	extra := ""
	if c := strings.TrimSpace(s.cfg.AbuseContact); c != "" {
		extra = `<p style="color:#8888">To escalate, contact: ` + contactLink(c) + `</p>`
	}
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8">`+
		`<meta name="viewport" content="width=device-width,initial-scale=1">`+
		`<meta name="robots" content="noindex,nofollow"><title>reported</title>`+
		`<style>:root{color-scheme:dark light}body{font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;`+
		`max-width:460px;margin:0 auto;padding:52px 22px;text-align:center}a{color:#4f63ff}</style></head><body>`+
		`<h1 style="font-size:18px">⚑ Thank you</h1>`+
		`<p>This content has been reported to the person hosting this link.</p>%s</body></html>`, extra)
}

// reportAlert notifies the owner that a viewer used the ⚑ report button,
// throttled (like probeAlert) so the button can't be used to notification-bomb.
func (s *share) reportAlert(who, label string) {
	if s.cfg.NoNotify {
		return
	}
	s.reportMu.Lock()
	if time.Since(s.lastReport) < 10*time.Second {
		s.reportMu.Unlock()
		return
	}
	s.lastReport = time.Now()
	s.reportMu.Unlock()
	go notify("tshare — content reported ⚑", fmt.Sprintf("a viewer reported %q (from %s)", label, who))
}

// ---------------------------------------------------------------------------
// zip streaming

func (s *share) handleZip(w *respRec, r *http.Request, dirRel string) {
	if r.Method != http.MethodGet {
		http.Error(w, "405", http.StatusMethodNotAllowed)
		return
	}
	if s.mode == "file" || s.mode == "inbox" || s.mode == "room" || s.mode == "call" {
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
