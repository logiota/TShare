//go:build unix

package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

// The arg splitter for `tshare run -- cmd` has to know every flag tshare owns
// and which ones consume the next token. Hand-written copies of that list drifted
// (20 value-taking flags were missing, and the --__daemon markers had to be
// appended by hand), so the sets are derived from registerFlags. This pins that.
func TestTshareFlagsMatchRegisterFlags(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerFlags(fs, defaultConfig())

	n := 0
	fs.VisitAll(func(f *flag.Flag) {
		n++
		if !isTshareFlag("--" + f.Name) {
			t.Errorf("--%s is a real flag but the run splitter doesn't know it", f.Name)
		}
		b, isBool := f.Value.(interface{ IsBoolFlag() bool })
		wantValue := !(isBool && b.IsBoolFlag())
		if got := runValueFlag("--" + f.Name); got != wantValue {
			t.Errorf("runValueFlag(--%s) = %v, want %v", f.Name, got, wantValue)
		}
		if strings.HasPrefix(f.Name, "__") && !tshareInternalFlag("--"+f.Name) {
			t.Errorf("--%s is internal but wasn't detected as such", f.Name)
		}
	})
	if n < 50 {
		t.Fatalf("only %d flags introspected — registerFlags wiring looks broken", n)
	}
}

func TestFlagClassification(t *testing.T) {
	for _, tc := range []struct {
		tok        string
		known, val bool
	}{
		{"--name", true, true}, {"--tmux", true, false}, {"-p", true, true},
		{"--persist", true, false}, {"--__id", true, true}, {"--__daemon", true, false},
		{"--turn-user", true, true}, // was missing from the old hand-written table
		{"node", false, false}, {"--not-a-tshare-flag", false, false},
	} {
		if got := isTshareFlag(tc.tok); got != tc.known {
			t.Errorf("isTshareFlag(%q) = %v, want %v", tc.tok, got, tc.known)
		}
		if got := runValueFlag(tc.tok); got != tc.val {
			t.Errorf("runValueFlag(%q) = %v, want %v", tc.tok, got, tc.val)
		}
	}
	if tshareInternalFlag("--name") {
		t.Error("--name must not count as an internal marker")
	}
}

// Each file registers its own subcommands from init(). A lost registration makes
// `tshare run …` fall through to the share engine and try to SHARE the command —
// silent and confusing, so assert the table.
func TestSubcommandsRegistered(t *testing.T) {
	for _, name := range []string{
		"ls", "list", "rm", "stop", "set", "extend", "info", "doctor", "panic",
		"run", "host", "tmux", "room", "kuma", "dash", "dashboard",
		"agent", "service", "resume", "decrypt", "template", "version", "help",
	} {
		if commands[name] == nil {
			t.Errorf("subcommand %q is not registered", name)
		}
	}
	if defaultRun == nil {
		t.Error("the default share engine is not registered")
	}
}

// A value flag's value must never become the start of the run command. The old
// hand-written table missed 20 value-taking flags, so `tshare run --turn-user
// bob npm start` treated "bob" as the command.
func TestSplitRunArgsConsumesValueFlags(t *testing.T) {
	for _, argv := range [][]string{
		{"--turn-user", "bob", "python3", "-m", "http.server"},
		{"--mirotalk-port", "7701", "node", "app.js"},
		{"--kuma-dir", "/tmp/k", "npm", "start"},
		{"--token-len", "24", "npm", "start"},
	} {
		flags, cmd := splitRunArgs(argv)
		if len(cmd) == 0 || cmd[0] == argv[1] || strings.HasPrefix(cmd[0], "-") {
			t.Errorf("%v: value leaked into the command: flags=%v cmd=%v", argv, flags, cmd)
		}
	}
}
