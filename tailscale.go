//go:build unix

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

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

// resolvesPublicly reports whether host has a public A/AAAA record, asking a
// public resolver directly (not the local one, which on a tailnet answers for
// *.ts.net via MagicDNS and would give a false positive). This is exactly what
// an off-tailnet visitor's resolver would return for a Funnel link.
func resolvesPublicly(host string) bool {
	for _, ns := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", ns)
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		ips, err := r.LookupHost(ctx, host)
		cancel()
		if err == nil && len(ips) > 0 {
			return true
		}
	}
	return false
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
