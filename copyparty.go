//go:build unix

package main

import (
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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

// copypartyPerm returns the anonymous volume permission string for this share.
//
//	r   — list + download (default folder share, or --ro)
//	w   — upload-only drop box (default -u inbox)
//	rw  — collaborative (--allow-upload)
//	A   — full rights rwmda. (--full): read/write/move/delete/admin/dots
func (s *share) copypartyPerm() string {
	c := s.cfg
	if c.Full {
		return "A"
	}
	if c.ReadOnly {
		return "r"
	}
	switch {
	case s.mode == "inbox":
		return "w"
	case s.upDir != "":
		return "rw"
	default:
		return "r"
	}
}

// startCopyparty launches copyparty on a loopback port serving the share's
// folder at the volume location /<token> — through the shared managed-server
// engine, so it's health-checked, crash-detected, recorded in the share's
// state and reaped with the share like every other server — then builds the
// reverse proxy.
func startCopyparty(s *share) (*serverProc, error) {
	c := s.cfg
	inv := copypartyInvocation(c)
	if inv == nil {
		return nil, errors.New("copyparty not found (pip install copyparty, or set --copyparty-bin)")
	}
	dir := s.roots[0].Abs
	if s.mode == "inbox" {
		dir = s.upDir
	}
	perm := s.copypartyPerm()
	port, err := freePort()
	if err != nil {
		return nil, err
	}

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
	// tee: copyparty's own warnings stay visible live (it runs with -q, so this
	// is errors only); a crash at startup is reported with its log tail.
	p, err := s.launchServer(srvSpec{
		name: "copyparty-" + s.id, argv: append(inv[:1:1], args...),
		port: port, wait: 15 * time.Second, tee: true,
	})
	if err != nil {
		return nil, err
	}
	s.adopt(p)
	// keepHost: copyparty builds its links from the visitor's Host header
	target := &url.URL{Scheme: "http", Host: "127.0.0.1:" + strconv.Itoa(port)}
	s.cpProxy = newProxy(target, c, "folder backend", true)
	return p, nil
}
