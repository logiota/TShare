//go:build unix

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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
// --hub: web-grab jobs (paste a URL → the host downloads it into the hub folder)

type jobHub struct {
	dir  string
	mu   sync.Mutex
	jobs map[string]*hubJob
	ord  []string // newest-first job ids
	note string
}

type hubJob struct {
	ID      string    `json:"id"`
	URL     string    `json:"url"`
	Name    string    `json:"name"`
	Pct     float64   `json:"pct"`
	Status  string    `json:"status"` // running | done | error
	Err     string    `json:"err,omitempty"`
	Size    int64     `json:"size"`
	Started time.Time `json:"started"`
}

func newJobHub(dir string) *jobHub { return &jobHub{dir: dir, jobs: map[string]*hubJob{}} }

func (h *jobHub) add(url string) *hubJob {
	h.mu.Lock()
	defer h.mu.Unlock()
	j := &hubJob{ID: randToken(6), URL: url, Name: "resolving…", Status: "running", Started: time.Now()}
	h.jobs[j.ID] = j
	h.ord = append([]string{j.ID}, h.ord...)
	if len(h.ord) > 50 { // cap history
		old := h.ord[50:]
		h.ord = h.ord[:50]
		for _, id := range old {
			delete(h.jobs, id)
		}
	}
	return j
}

func (h *jobHub) update(id string, fn func(*hubJob)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if j := h.jobs[id]; j != nil {
		fn(j)
	}
}

func (h *jobHub) list() []hubJob {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]hubJob, 0, len(h.ord))
	for _, id := range h.ord {
		if j := h.jobs[id]; j != nil {
			out = append(out, *j)
		}
	}
	return out
}

// blockedIP reports whether an IP is one a web-grab must never reach:
// loopback, private, link-local (incl. the 169.254.169.254 cloud-metadata
// endpoint), or unspecified.
func blockedIP(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// privateHost is the friendly pre-check: resolve the URL host and refuse if any
// address is internal. It is only advisory — DNS can rebind and redirects can
// retarget between this check and the connection — so the authoritative guard
// is grabClient's socket-level Control (which validates the ACTUAL connected IP
// on every hop) plus its redirect re-check.
func privateHost(u *url.URL) bool {
	ips, err := net.LookupIP(u.Hostname())
	if err != nil {
		return true // can't resolve → refuse rather than risk it
	}
	for _, ip := range ips {
		if blockedIP(ip) {
			return true
		}
	}
	return false
}

// grabClient fetches web-grabs with SSRF closed at two layers that between them
// defeat redirect-to-internal AND DNS rebinding:
//   - DialContext.Control validates the real IP the socket is about to connect
//     to (runs for the original host and every redirect hop / candidate IP).
//   - CheckRedirect re-runs the host check on each redirect target and caps hops.
var grabClient = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   20 * time.Second,
			KeepAlive: 30 * time.Second,
			Control: func(network, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				if blockedIP(net.ParseIP(host)) {
					return fmt.Errorf("refusing to connect to internal address %s", host)
				}
				return nil
			},
		}).DialContext,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 8 {
			return errors.New("too many redirects")
		}
		if privateHost(req.URL) {
			return errors.New("refusing redirect to an internal address")
		}
		return nil
	},
}

var directFileExtRe = regexp.MustCompile(`(?i)\.(zip|rar|7z|tar|gz|tgz|bz2|xz|iso|dmg|pkg|exe|apk|bin|pdf|epub|mobi|jpe?g|png|gif|webp|svg|txt|csv|json|xml|docx?|xlsx?|pptx?|mp3|m4a|flac|wav)$`)

// startGrab launches a web-grab in the background: yt-dlp for site/video URLs
// (falling back to a plain fetch), or a direct HTTP download for file URLs.
func (s *share) startGrab(rawURL string) (*hubJob, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("enter a full http(s):// URL")
	}
	j := s.jobs.add(rawURL)
	go func() {
		var derr error
		// SSRF pre-check up front so it covers BOTH the yt-dlp and fetch paths
		// (yt-dlp does its own networking, so this initial-host check is the only
		// guard we can put in front of it; the fetch path is additionally guarded
		// at the socket level by grabClient against redirects/DNS-rebinding).
		if privateHost(u) {
			derr = errors.New("refusing to fetch a private/loopback/link-local address")
		} else {
			ytUsable := false
			if _, e := ytBin(); e == nil {
				ytUsable = true
			}
			// A URL that ends in a known file extension → direct fetch. Otherwise
			// prefer yt-dlp (it resolves sites/videos), falling back to a fetch.
			if directFileExtRe.MatchString(u.Path) || !ytUsable {
				derr = s.grabFetch(j, u)
			} else {
				if derr = s.grabYt(j, rawURL); derr != nil {
					derr = s.grabFetch(j, u) // yt-dlp couldn't → try a plain download
				}
			}
		}
		newest := s.newestHubFile(j.Started)
		finalName := ""
		s.jobs.update(j.ID, func(x *hubJob) {
			if derr != nil {
				x.Status, x.Err = "error", derr.Error()
			} else {
				x.Status, x.Pct = "done", 100
				if (x.Name == "resolving…" || x.Name == "") && newest != "" {
					x.Name = newest // yt-dlp output parse missed it → use the file that landed
				}
			}
			finalName = x.Name
		})
		if derr == nil && !s.cfg.NoNotify {
			go notify("tshare hub", "grabbed "+finalName)
		}
	}()
	return j, nil
}

// newestHubFile returns the name of the most-recently-modified regular file in
// the hub folder that was touched at/after since — the reliable way to name a
// yt-dlp grab whose console output we couldn't parse.
func (s *share) newestHubFile(since time.Time) string {
	des, err := os.ReadDir(s.jobs.dir)
	if err != nil {
		return ""
	}
	name, best := "", time.Time{}
	for _, de := range des {
		if de.IsDir() || strings.HasPrefix(de.Name(), ".") {
			continue
		}
		if fi, err := de.Info(); err == nil && !fi.ModTime().Before(since.Add(-time.Second)) && fi.ModTime().After(best) {
			name, best = de.Name(), fi.ModTime()
		}
	}
	return name
}

// grabFetch downloads a file URL straight into the hub folder, size-streamed
// with live progress. SSRF is closed by grabClient at the socket level (real
// connected IP validated on every hop) plus a redirect re-check — so redirects
// to internal hosts and DNS rebinding are both refused, not just the initial URL.
func (s *share) grabFetch(j *hubJob, u *url.URL) error {
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "tshare/"+version)
	resp, err := grabClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %s", resp.Status)
	}
	name := sanitizeName(fetchName(resp, u.String()))
	if name == "" {
		name = "download-" + j.ID
	}
	dst, fname, err := createUnique(s.jobs.dir, name)
	if err != nil {
		return err
	}
	s.jobs.update(j.ID, func(x *hubJob) { x.Name = fname })
	total := resp.ContentLength
	pw := &progWriter{total: total, onPct: func(p float64, n int64) {
		s.jobs.update(j.ID, func(x *hubJob) { x.Pct, x.Size = p, n })
	}}
	_, err = io.Copy(io.MultiWriter(dst, pw), resp.Body)
	dst.Close()
	if err != nil {
		os.Remove(filepath.Join(s.jobs.dir, fname))
		return err
	}
	return nil
}

// grabYt runs yt-dlp into the hub folder, reusing ytArgs, and drives the job's
// percent from its --newline progress.
func (s *share) grabYt(j *hubJob, rawURL string) error {
	bin, err := ytBin()
	if err != nil {
		return err
	}
	yc := &config{Paths: []string{rawURL}} // default smart MP4 selection
	// force --newline and DROP --no-progress so yt-dlp emits the per-line
	// percentage we parse to drive the job's progress bar.
	args := append([]string{"--newline"}, dropArg(ytArgs(yc, s.jobs.dir), "--no-progress")...)
	cmd := exec.Command(bin, args...)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr, cmd.Stdin = pw, pw, nil
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if m := ytPctRe.FindStringSubmatch(line); m != nil {
				if p, e := strconv.ParseFloat(m[1], 64); e == nil {
					s.jobs.update(j.ID, func(x *hubJob) {
						if p > x.Pct {
							x.Pct = p
						}
					})
				}
			}
			if m := ytDestRe.FindStringSubmatch(line); m != nil {
				dest := m[1]
				if dest == "" {
					dest = m[2] // the "Merging formats into" alternative
				}
				if dest != "" {
					n := filepath.Base(strings.TrimSpace(dest))
					s.jobs.update(j.ID, func(x *hubJob) { x.Name = n })
				}
			}
		}
	}()
	runErr := cmd.Run()
	pw.Close()
	if runErr != nil {
		return fmt.Errorf("yt-dlp failed")
	}
	return nil
}

var ytDestRe = regexp.MustCompile(`Destination: (.+)$|Merging formats into "(.+)"`)

// progWriter tracks copy progress and reports percent (throttled by the caller
// via a simple last-percent gate).
type progWriter struct {
	total   int64
	written int64
	last    float64
	onPct   func(pct float64, n int64)
}

func (p *progWriter) Write(b []byte) (int, error) {
	n := len(b)
	p.written += int64(n)
	pct := 0.0
	if p.total > 0 {
		pct = float64(p.written) * 100 / float64(p.total)
	}
	if pct-p.last >= 1 || p.total <= 0 {
		p.last = pct
		p.onPct(pct, p.written)
	}
	return n, nil
}

// handleHub serves the --hub control endpoints (all behind the token/password
// gate). Files land in / are served from the hub folder.
func (s *share) handleHub(w *respRec, r *http.Request, rel string, urlBase string) {
	switch {
	case rel == "" && r.Method == http.MethodGet:
		s.renderHub(w, urlBase)
	case rel == "__grab" && r.Method == http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		j, err := s.startGrab(r.FormValue("url"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// snapshot the job under the lock — the grab goroutine mutates *j
		// concurrently (all its writes are lock-held), so read it the same way.
		s.jobs.mu.Lock()
		snap := *j
		s.jobs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(snap)
		w.Write(b)
	case rel == "__jobs" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(s.jobs.list())
		w.Write(b)
	case rel == "__list" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(s.hubFiles())
		w.Write(b)
	case rel == "__rm" && r.Method == http.MethodPost:
		name := sanitizeName(r.FormValue("name"))
		if name == "" || strings.ContainsAny(r.FormValue("name"), "/\\") {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		if err := os.Remove(filepath.Join(s.jobs.dir, name)); err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	case rel == "__note":
		if r.Method == http.MethodPost {
			s.jobs.mu.Lock()
			s.jobs.note = r.FormValue("note")
			if len(s.jobs.note) > 20000 {
				s.jobs.note = s.jobs.note[:20000]
			}
			s.jobs.mu.Unlock()
		}
		s.jobs.mu.Lock()
		note := s.jobs.note
		s.jobs.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(map[string]string{"note": note})
		w.Write(b)
	case rel == "manifest.webmanifest":
		s.serveHubManifest(w, urlBase)
	case rel == "apple-touch-icon.png" || rel == "icon.png":
		serveHubIcon(w)
	default:
		http.NotFound(w, r)
	}
}

// hubFiles lists the regular files in the hub folder (name/size/mtime), newest
// first — the "local" side of the 2-way remote.
func (s *share) hubFiles() []map[string]any {
	des, err := os.ReadDir(s.jobs.dir)
	if err != nil {
		return []map[string]any{}
	}
	type fe struct {
		name string
		size int64
		mod  time.Time
	}
	var fs []fe
	for _, de := range des {
		if de.IsDir() || strings.HasPrefix(de.Name(), ".") {
			continue
		}
		if fi, err := de.Info(); err == nil {
			fs = append(fs, fe{de.Name(), fi.Size(), fi.ModTime()})
		}
	}
	sort.Slice(fs, func(i, j int) bool { return fs[i].mod.After(fs[j].mod) })
	out := make([]map[string]any, 0, len(fs))
	for _, f := range fs {
		out = append(out, map[string]any{"name": f.name, "size": f.size, "sizeh": humanSize(f.size), "mod": f.mod.Unix()})
	}
	return out
}
