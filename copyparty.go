//go:build unix

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

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
	if s.senderKey != "" { // --p2p folder: our transfer page + __rtc endpoints
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
	proxy.BufferPool = proxyBufPool              // reuse 64 KiB buffers (less GC)
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
