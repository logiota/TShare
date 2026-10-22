//go:build unix

package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseHelpRows(t *testing.T) {
	text := `SECURITY FLAGS
  -p, --password <pw>     require a password (HTTP Basic)
                          (or set env TSHARE_PASSWORD)
      --abuse-contact <s> show a takedown line
      --mirotalk-dir/-port   where it lives / its port

DOWNLOADS & STREAMS (URLs, yt-dlp, stdin)
  -Y, --yt-dlp            force yt-dlp
`
	got := map[string]helpEntry{}
	for _, e := range parseHelp(text) {
		for _, n := range e.names {
			got[n] = e
		}
	}
	pw := got["password"]
	if pw.hint != "<pw>" || pw.section != "SECURITY FLAGS" || !strings.Contains(pw.desc, "TSHARE_PASSWORD") {
		t.Errorf("password row: %+v", pw)
	}
	if got["p"].desc != pw.desc {
		t.Error("-p and --password are one row")
	}
	if ab := got["abuse-contact"]; ab.hint != "<s>" || ab.desc != "show a takedown line" {
		t.Errorf("one-space row: hint=%q desc=%q", ab.hint, ab.desc)
	}
	if got["mirotalk-port"].desc != "where it lives / its port" {
		t.Error("--x-dir/-port should document both --x-dir and --x-port")
	}
	if got["yt-dlp"].section != "DOWNLOADS & STREAMS" {
		t.Errorf("a heading with a lowercase parenthetical: section=%q", got["yt-dlp"].section)
	}
}

// Every real option is a wizard row, aliases fold into one row, and every row
// is explained by --help — so a new flag without docs fails here.
func TestWizardCoversEveryOption(t *testing.T) {
	opts := wizOptions()
	owner := map[string]*wizOpt{}
	for _, o := range opts {
		for _, n := range o.names {
			if owner[n] != nil {
				t.Errorf("--%s is in two rows", n)
			}
			owner[n] = o
		}
		if o.desc == "(not described in --help)" {
			t.Errorf("%s has no explanation in --help — add a row to usageText", o.label())
		}
		if o.section == otherSection {
			t.Errorf("%s isn't under any --help section", o.label())
		}
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerFlags(fs, defaultConfig())
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.HasPrefix(f.Name, "__") && f.Name != "webwiz" && owner[f.Name] == nil {
			t.Errorf("--%s is missing from the wizard", f.Name)
		}
	})
	if o := owner["password"]; o == nil || o != owner["p"] || o.primary != "password" || !o.secret {
		t.Error("-p/--password should be one secret row led by --password")
	}
	if o := owner["site"]; o == nil || o != owner["web"] {
		t.Error("--site/--web should be one row")
	}
}

func TestWizardComposesTheCommand(t *testing.T) {
	site := t.TempDir()
	os.WriteFile(filepath.Join(site, "index.html"), []byte("<h1>x</h1>"), 0o644)
	file := filepath.Join(t.TempDir(), "report.pdf")
	os.WriteFile(file, []byte("%PDF"), 0o644)

	// prefilled from the command line; a website folder means `tshare host`
	w := newWizard([]string{"--webwiz", "-p", "hunter2", "--root", site})
	if !w.host {
		t.Fatal("a website folder should default to website mode")
	}
	got := strings.Join(w.argv(), " ")
	if want := "host " + site + " --password hunter2 --root"; got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
	if line := w.commandLine(true); strings.Contains(line, "hunter2") || !strings.Contains(line, "••••••") {
		t.Errorf("preview leaks the password: %q", line)
	}
	if line := w.commandLine(false); !strings.Contains(line, "hunter2") {
		t.Errorf("the printed command must work: %q", line)
	}

	// a file is a plain share; an option that's ON by default emits =false
	w = newWizard([]string{file})
	if w.host {
		t.Error("a file is not website mode")
	}
	for _, o := range w.opts {
		if o.primary == "copy" {
			if !o.on {
				t.Fatal("--copy is on by default, so it starts ticked")
			}
			o.on = false
		}
	}
	if got := strings.Join(w.argv(), " "); got != "--copy=false "+file {
		t.Errorf("argv = %q", got)
	}
}

func TestWizardPrintsAChecklistWithoutATerminal(t *testing.T) {
	var b bytes.Buffer
	newWizard(nil).printChecklist(&b)
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
