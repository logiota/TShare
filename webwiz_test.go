//go:build unix && !nowebwiz

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWizardPrintsAChecklistWithoutATerminal(t *testing.T) {
	var b bytes.Buffer
	newBuilder(nil).printChecklist(&b)
	out := b.String()
	for _, want := range []string{webSection, "--root", "--persist", "SECURITY FLAGS", "$ tshare"} {
		if !strings.Contains(out, want) {
			t.Errorf("checklist is missing %q", want)
		}
	}
	if strings.Index(out, webSection) > strings.Index(out, "SECURITY FLAGS") {
		t.Error("the website section should come first")
	}
}

func TestSplitKeys(t *testing.T) {
	got := splitKeys("\x1b[Bj \x1b[5~é\r")
	want := []string{"\x1b[B", "j", " ", "\x1b[5~", "é", "\r"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("splitKeys = %q, want %q", got, want)
	}
}
