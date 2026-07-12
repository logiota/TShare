//go:build unix

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

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

// haveExec reports whether an executable is on PATH.
func haveExec(name string) bool { _, err := exec.LookPath(name); return err == nil }

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
