//go:build unix && !nocleanup

package main

// `tshare cleanup`: clear away what crashed or killed shares leave behind —
// Tailscale mounts that point at nothing (visitors get an error page there),
// records of shares that are gone and any servers they left running, stale
// control sockets, and orphaned temp downloads.
//
// It only removes what is provably dead. A mount goes only when nothing
// listens behind it AND it is recognisably tshare's: a random-token path, or
// one a tshare record names. A dead mount that isn't recognisably tshare's is
// listed with the command to remove it by hand, and left alone. Resume records
// (--persist) are never touched — they're how shares come back after a reboot.
// `tshare cleanup -n` shows the plan without changing anything.
// Optional — build with -tags nocleanup to leave it out.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func init() { register(cmdCleanup, "cleanup", "clean") }

// A cleanup item is one thing found. do == nil means report only.
type cleanupItem struct {
	what  string
	bytes int64
	do    func() error
	hint  string // for report-only items: how to remove it by hand
}

func cmdCleanup(args []string) {
	fl := flag.NewFlagSet("cleanup", flag.ExitOnError)
	dry := fl.Bool("n", false, "dry run: show what would be removed, change nothing")
	fl.BoolVar(dry, "dry-run", false, "dry run: show what would be removed, change nothing")
	tsb := fl.String("tailscale-bin", "", "path to the tailscale CLI (or env TAILSCALE)")
	fl.Parse(args)

	items := planCleanup(*tsb)
	if len(items) == 0 {
		fmt.Println("  ✓ nothing to clean up")
		return
	}
	verb := "removed"
	if *dry {
		verb = "would remove"
	}
	removed, failed := 0, 0
	var reclaimed int64
	for _, it := range items {
		if it.do == nil {
			fmt.Printf("  · left alone: %s\n      to remove it yourself:  %s\n", it.what, it.hint)
			continue
		}
		if !*dry {
			if err := it.do(); err != nil {
				fmt.Printf("  ✗ couldn't remove %s: %v\n", it.what, err)
				failed++
				continue
			}
		}
		fmt.Printf("  ✓ %s %s\n", verb, it.what)
		removed++
		reclaimed += it.bytes
	}
	summary := fmt.Sprintf("%d removed", removed)
	if reclaimed > 0 {
		summary += ", " + humanSize(reclaimed) + " freed"
	}
	if *dry {
		summary = fmt.Sprintf("%d to remove", removed)
		if reclaimed > 0 {
			summary += ", " + humanSize(reclaimed) + " to free"
		}
	}
	if failed > 0 {
		summary += fmt.Sprintf(", %d failed", failed)
	}
	if *dry {
		summary += " — dry run, nothing changed (run without -n to do it)"
	}
	fmt.Println("\n  " + summary)
}

// planCleanup finds everything stale. Live shares, and anything they own, are
// never in the plan.
func planCleanup(tsBinPath string) []cleanupItem {
	var items []cleanupItem
	live := map[string]bool{}  // ids of running shares
	owned := map[string]bool{} // mount paths running shares hold ("" = the root)
	known := map[string]bool{} // mount paths any tshare record names, dead or alive
	deadRoot := false          // a stopped share recorded holding the root
	for _, r := range loadStates() {
		known[r.Token] = true
		if recAlive(r) {
			live[r.ID], owned[r.Token] = true, true
			if r.RootMount {
				owned[""] = true
			}
			continue
		}
		deadRoot = deadRoot || r.RootMount
		r := r
		items = append(items, cleanupItem{
			what: fmt.Sprintf("record of stopped share %s (%s)", r.ID, r.URL),
			do: func() error {
				reapProcs(r.Procs, syscall.SIGTERM) // servers it launched and never stopped
				return os.Remove(stateFile(r.ID))
			},
		})
	}
	if des, err := os.ReadDir(persistDir()); err == nil {
		for _, de := range des {
			var p persistRec
			if b, err := os.ReadFile(filepath.Join(persistDir(), de.Name())); err == nil && json.Unmarshal(b, &p) == nil && p.Token != "" {
				known[p.Token] = true
			}
		}
	}
	items = append(items, staleMounts(tsBinPath, owned, known, deadRoot)...)
	items = append(items, staleSockets(live)...)
	items = append(items, staleTemp(live, time.Hour)...)
	return items
}

// serveStatus is the part of `tailscale serve status --json` cleanup reads.
type serveStatus struct {
	Web map[string]struct {
		Handlers map[string]struct{ Proxy string }
	}
	AllowFunnel map[string]bool
}

func staleMounts(tsBinPath string, owned, known map[string]bool, deadRoot bool) []cleanupItem {
	bin, err := tsBin(&config{TSBin: tsBinPath})
	if err != nil {
		return nil // no tailscale here: no mounts to check
	}
	out, err := exec.Command(bin, "serve", "status", "--json").Output()
	if err != nil {
		return nil
	}
	var st serveStatus
	if json.Unmarshal(out, &st) != nil {
		return nil
	}
	var items []cleanupItem
	for _, hp := range sortedKeys(st.Web) {
		host, portStr, err := net.SplitHostPort(hp)
		if err != nil {
			continue
		}
		port, _ := strconv.Atoi(portStr)
		origin := "https://" + host
		if port != 443 {
			origin += ":" + portStr
		}
		c := &config{TSBin: tsBinPath, HTTPSPort: port, Tailnet: !st.AllowFunnel[hp]}
		for _, mount := range sortedKeys(st.Web[hp].Handlers) {
			target := st.Web[hp].Handlers[mount].Proxy
			name := strings.Trim(mount, "/")
			if target == "" || owned[name] || proxyAnswers(target) {
				continue // a file/text handler, a live share's, or something answers
			}
			what := fmt.Sprintf("dead mount %s%s → %s (nothing listening)", origin, mount, target)
			ours := (name == "" && deadRoot) || (name != "" && (known[name] || tokenLike(name)))
			if !ours {
				items = append(items, cleanupItem{what: what + ", not recognisably tshare's",
					hint: fmt.Sprintf("tailscale %s --https=%d --set-path=%s off", verb(c), port, mount)})
				continue
			}
			items = append(items, cleanupItem{what: what, do: func() error { return tsUnmount(c, name) }})
		}
	}
	return items
}

// proxyAnswers reports whether a mount's target accepts connections. Anything
// that isn't a loopback address can't be judged from here, so it counts as
// answering (and is left alone).
func proxyAnswers(target string) bool {
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return true
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "https+insecure": "443"}[u.Scheme]
		if port == "" {
			port = "80"
		}
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return true
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 700*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

var tokenAlphabetRe = regexp.MustCompile(`^[A-Za-z0-9_-]{12,64}$`)

// tokenLike recognises tshare's random mount paths (url-safe base64, 16 chars
// by default) without mistaking a human path like /my-dashboard-app for one.
func tokenLike(name string) bool {
	if !tokenAlphabetRe.MatchString(name) {
		return false
	}
	var lower, upperOrDigit bool
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			upperOrDigit = true
		}
	}
	return lower && upperOrDigit
}

func staleSockets(live map[string]bool) []cleanupItem {
	des, err := os.ReadDir(ctlDir())
	if err != nil {
		return nil
	}
	var items []cleanupItem
	for _, de := range des {
		id := strings.TrimSuffix(de.Name(), ".sock")
		p := filepath.Join(ctlDir(), de.Name())
		if live[id] || newestChange(p).After(time.Now().Add(-time.Minute)) {
			continue
		}
		items = append(items, cleanupItem{what: "control socket of stopped share " + id,
			do: func() error { return os.Remove(p) }})
	}
	return items
}

// staleTemp finds downloads and buffers in ~/.tshare/tmp that no running
// share owns. One still being written (a long download whose share isn't up
// yet) is spared: anything changed within minAge — judged by the newest file
// inside, not the folder's own timestamp — stays.
func staleTemp(live map[string]bool, minAge time.Duration) []cleanupItem {
	base := filepath.Join(filepath.Dir(stateDir()), "tmp")
	des, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var items []cleanupItem
	for _, de := range des {
		name := de.Name()
		if strings.HasPrefix(name, ".") || belongsToLive(name, live) {
			continue
		}
		p := filepath.Join(base, name)
		if newestChange(p).After(time.Now().Add(-minAge)) {
			continue
		}
		size := diskUsage(p)
		items = append(items, cleanupItem{what: fmt.Sprintf("orphaned temp %s (%s)", name, humanSize(size)),
			bytes: size, do: func() error { return os.RemoveAll(p) }})
	}
	return items
}

// belongsToLive: temp names embed the share id (yt-<id>, grow-<id>-<file>).
func belongsToLive(name string, live map[string]bool) bool {
	for id := range live {
		if strings.Contains(name, id) {
			return true
		}
	}
	return false
}

// newestChange is the latest modification time of p or anything inside it.
func newestChange(p string) time.Time {
	var newest time.Time
	filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if fi, err := d.Info(); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
		return nil
	})
	return newest
}

func diskUsage(p string) int64 {
	var n int64
	filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
