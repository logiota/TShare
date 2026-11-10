//go:build unix && !nocleanup

package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCleanupRegisters(t *testing.T) {
	for _, name := range []string{"cleanup", "clean"} {
		if commands[name] == nil {
			t.Errorf("subcommand %q is not registered", name)
		}
	}
}

func TestTokenLike(t *testing.T) {
	for name, want := range map[string]bool{
		"ITwalnUMQL49zVS8": true, "cFfiN3uV3RO5s-vd": true, "yuE4UqTDGyF2od5f": true,
		"my-dashboard-app": false, "api": false, "blog": false, "": false, "a/b": false,
	} {
		if got := tokenLike(name); got != want {
			t.Errorf("tokenLike(%q) = %v, want %v", name, got, want)
		}
	}
}

// A fake `tailscale` prints a crafted mount list, so every rule is exercised
// without touching the machine's real Tailscale config.
func TestStaleMountsOnlyRemovesWhatsProvablyDeadAndOurs(t *testing.T) {
	alive, _ := net.Listen("tcp", "127.0.0.1:0")
	defer alive.Close()
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close() // nothing listens here any more

	status := `{"Web":{"h.ts.net:443":{"Handlers":{` +
		`"/ITwalnUMQL49zVS8":{"Proxy":"http://` + deadAddr + `"},` + // dead + token-like → remove
		`"/liveShareTok1234":{"Proxy":"http://` + deadAddr + `"},` + // owned by a live share → keep
		`"/aLiveServer9Xyz":{"Proxy":"http://` + alive.Addr().String() + `"},` + // answers → keep
		`"/my-dashboard":{"Proxy":"http://` + deadAddr + `"},` + // dead, human path → report only
		`"/vanity":{"Proxy":"http://` + deadAddr + `"},` + // dead, named by a tshare record → remove
		`"/remoteThing9Ab":{"Proxy":"http://192.0.2.10:80"},` + // not loopback → can't judge → keep
		`"/":{"Proxy":"http://` + deadAddr + `"}` + // dead root, no tshare record held it → report
		`}}},"AllowFunnel":{"h.ts.net:443":true}}`
	fake := filepath.Join(t.TempDir(), "tailscale")
	os.WriteFile(fake, []byte("#!/bin/sh\ncat <<'EOF'\n"+status+"\nEOF\n"), 0o755)

	items := staleMounts(fake, map[string]bool{"liveShareTok1234": true}, map[string]bool{"vanity": true}, false)
	var remove, report []string
	for _, it := range items {
		if it.do != nil {
			remove = append(remove, it.what)
		} else {
			report = append(report, it.what)
		}
	}
	want := func(list []string, path string) bool {
		for _, s := range list {
			if strings.Contains(s, "h.ts.net"+path+" ") {
				return true
			}
		}
		return false
	}
	if len(remove) != 2 || !want(remove, "/ITwalnUMQL49zVS8") || !want(remove, "/vanity") {
		t.Errorf("should remove exactly the dead token mount and the recorded one, got %v", remove)
	}
	if len(report) != 2 || !want(report, "/my-dashboard") || !want(report, "/") {
		t.Errorf("should only report the dead human path and the unclaimed root, got %v", report)
	}
}

// A download whose share isn't up yet keeps writing into its folder; the folder
// itself looks old. It must survive cleanup.
func TestStaleTempSparesWorkInProgress(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	tmp := filepath.Join(home, ".tshare", "tmp")
	old := time.Now().Add(-3 * time.Hour)
	for _, d := range []string{"yt-abandn", "yt-inprog", "yt-LIVEid"} {
		os.MkdirAll(filepath.Join(tmp, d), 0o700)
		f := filepath.Join(tmp, d, "video.part")
		os.WriteFile(f, []byte("x"), 0o600)
		os.Chtimes(f, old, old)
		os.Chtimes(filepath.Join(tmp, d), old, old)
	}
	os.WriteFile(filepath.Join(tmp, "yt-inprog", "video.part"), []byte("still downloading"), 0o600) // fresh

	items := staleTemp(map[string]bool{"LIVEid": true}, time.Hour)
	if len(items) != 1 || !strings.Contains(items[0].what, "yt-abandn") {
		t.Fatalf("only the abandoned download should go, got %v", items)
	}
	if err := items[0].do(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "yt-abandn")); !os.IsNotExist(err) {
		t.Error("the abandoned download is still there")
	}
}
