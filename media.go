//go:build unix

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

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
