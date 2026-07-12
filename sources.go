//go:build unix

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

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
