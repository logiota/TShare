//go:build unix

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// tailscale integration

type tsInfo struct {
	BackendState string
	Self         struct{ DNSName string }
	CertDomains  []string
}

func tsBin(c *config) (string, error) { return tailscaleBin(c.TSBin) }

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

// tsUnmount removes a funnel/serve mount. Most callers are best-effort
// cleanup and ignore the result; `tshare cleanup` checks it.
func tsUnmount(c *config, mount string) error {
	bin, err := tsBin(c)
	if err != nil {
		return err
	}
	args := []string{verb(c),
		"--https=" + strconv.Itoa(c.HTTPSPort),
		"--set-path=/" + mount, "off"}
	if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
