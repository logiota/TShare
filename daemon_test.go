//go:build unix

package main

import (
	"strings"
	"testing"
)

// The -b child must always see its daemon markers as tshare flags. When they
// were appended to argv they landed inside `run … -- cmd`, the child never knew
// it was the daemon, and re-daemonized itself in an unbounded chain.
func TestInsertArgsKeepsDaemonMarkersOutOfRunCommand(t *testing.T) {
	for _, argv := range [][]string{
		{"run", "-b", "--port", "8766", "--", "python3", "-m", "http.server", "8766"},
		{"run", "-b", "python3", "-m", "http.server"},
		{"run", "-b", "--", "node", "app.js", "--name", "demo", "--tmux"},
	} {
		got := insertArgs(argv, "--__daemon", "--__id", "abc123")
		if got[0] != "run" {
			t.Fatalf("%v: subcommand moved: %v", argv, got)
		}
		flags, cmd := splitRunArgs(got[1:])
		for _, a := range cmd {
			if strings.HasPrefix(a, "--__") || a == "abc123" {
				t.Errorf("%v: daemon marker leaked into the command: %v", argv, cmd)
			}
		}
		c := defaultConfig()
		if err := parseArgs(flags, c); err != nil {
			t.Fatalf("%v: parse: %v", argv, err)
		}
		if !c.daemonChild || c.daemonID != "abc123" {
			t.Errorf("%v: child wouldn't know it's the daemon (child=%v id=%q)", argv, c.daemonChild, c.daemonID)
		}
	}
}

func TestInsertArgsBareShare(t *testing.T) {
	got := insertArgs([]string{"-b", "report.pdf"}, "--__daemon", "--__id", "x")
	want := []string{"--__daemon", "--__id", "x", "-b", "report.pdf"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("got %v, want %v", got, want)
	}
}
