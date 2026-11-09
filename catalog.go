//go:build unix

package main

// The option catalogue and the command builder: the model behind every
// point-and-click front end (the --webwiz terminal checklist, `tshare gui`,
// the MCP server for AI agents).
//
// None of it is a second copy of the options. Rows come from registerFlags
// (aliases folded together by the variable they set, or by sharing a --help
// row); explanations and sections come from the --help text. A flag can't be
// missing here, and its explanation can't drift from --help.

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// the option catalogue: flag set + --help, joined

type helpEntry struct {
	section string
	names   []string // as listed: "p", "password"
	hint    string   // "<pw>", "[dir]"
	desc    string
	order   int
}

var (
	helpHeadingRe = regexp.MustCompile(`^[A-Z][A-Z0-9 &/,'-]+$`)
)

// parseHelp reads the flag rows out of a --help text: section headings are
// all-caps lines, a flag row starts with "-x, --long <hint>" and its
// explanation continues on deeper-indented lines.
func parseHelp(text string) []helpEntry {
	var out []helpEntry
	section := ""
	var cur []int // the entries a continuation line extends (a combo row has two)
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "":
			cur = nil
		case !strings.HasPrefix(line, " ") && helpHeadingRe.MatchString(headingName(trimmed)):
			section, cur = headingName(trimmed), nil
		case strings.HasPrefix(trimmed, "-") && len(line)-len(strings.TrimLeft(line, " ")) <= 6:
			spec, desc := splitHelpRow(line)
			groups, hint := splitHelpSpec(spec)
			cur = nil
			for _, g := range groups {
				out = append(out, helpEntry{section: section, names: g, hint: hint, desc: desc, order: len(out)})
				cur = append(cur, len(out)-1)
			}
		case cur != nil && strings.HasPrefix(line, "                    "):
			for _, i := range cur {
				out[i].desc = strings.TrimSpace(out[i].desc + " " + trimmed)
			}
		default:
			cur = nil
		}
	}
	return out
}

// helpDescCol is where --help starts every explanation column.
const helpDescCol = 26

// headingName drops a heading's parenthetical: "MEDIA TRANSFORMS (need …)".
func headingName(h string) string {
	if i := strings.Index(h, " ("); i > 0 {
		return h[:i]
	}
	return h
}

// splitHelpRow separates "  -p, --password <pw>     require a password" into
// spec and explanation. Most rows reach the explanation column with two or
// more spaces; a long spec can arrive with just one ("--abuse-contact <s> show"),
// so the column itself wins when it lines up.
func splitHelpRow(line string) (spec, desc string) {
	if len(line) > helpDescCol && line[helpDescCol-1] == ' ' && line[helpDescCol] != ' ' {
		return line[:helpDescCol], strings.TrimSpace(line[helpDescCol:])
	}
	body := strings.TrimLeft(line, " ")
	if i := strings.Index(body, "  "); i >= 0 {
		return body[:i], strings.TrimSpace(body[i:])
	}
	return body, ""
}

// splitHelpSpec turns a row's spec into alias groups: "-p, --password <pw>" is
// one option ([[p password]], "<pw>"), while "--mirotalk-dir/-port" is two
// options that share a row ([[mirotalk-dir] [mirotalk-port]]).
func splitHelpSpec(spec string) (groups [][]string, hint string) {
	var aliases []string
	for _, tok := range strings.Fields(strings.ReplaceAll(spec, ",", " ")) {
		switch {
		case strings.HasPrefix(tok, "-"):
			base, alt, combo := strings.Cut(strings.TrimLeft(tok, "-"), "/-")
			if !combo {
				aliases = append(aliases, base)
				continue
			}
			groups = append(groups, []string{base})
			if i := strings.LastIndex(base, "-"); i > 0 {
				groups = append(groups, []string{base[:i+1] + alt})
			}
		case hint == "":
			hint = tok
		default:
			hint += " " + tok
		}
	}
	if len(aliases) > 0 {
		groups = append([][]string{aliases}, groups...)
	}
	return groups, hint
}

type option struct {
	names   []string // every alias, short first
	primary string   // the name used in the composed command
	section string
	desc    string
	hint    string
	isBool  bool
	secret  bool
	order   int
	def     string // the flag's default, offered when you start typing a value
	defOn   bool   // a boolean that's ON by default (--copy, --lan)

	on    bool
	value string
}

func (o *option) flag() string {
	if len(o.primary) == 1 {
		return "-" + o.primary
	}
	return "--" + o.primary
}

// label is how a row names itself: "-p, --password".
func (o *option) label() string {
	var short []string
	for _, n := range o.names {
		if len(n) == 1 && n != o.primary {
			short = append(short, "-"+n)
		}
	}
	return strings.Join(append(short, o.flag()), ", ")
}

const otherSection = "OTHER"

// catalogOptions builds one row per real option. Aliases (-p/--password,
// --site/--web, --room/--mirotalk) are registered on the same variable, so
// they're folded by the address their flag.Value points at.
func catalogOptions() []*option {
	fs := flag.NewFlagSet("webwiz", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerFlags(fs, defaultConfig())

	helpEntries := parseHelp(usageText)
	help := map[string]helpEntry{}
	for _, e := range helpEntries {
		for _, n := range e.names {
			if _, seen := help[n]; !seen {
				help[n] = e
			}
		}
	}

	// Fold aliases into one row. Two signals, joined with a union-find: flags
	// registered on the same variable (-p/--password share a *string), and
	// flags --help lists together (-e, --expires wrap their duration in a
	// fresh flag.Value each, so pointers alone miss them).
	var flags []*flag.Flag
	fs.VisitAll(func(f *flag.Flag) {
		if !strings.HasPrefix(f.Name, "__") && f.Name != "webwiz" {
			flags = append(flags, f)
		}
	})
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}
	union := func(a, b string) { parent[find(a)] = find(b) }
	for _, f := range flags {
		parent[f.Name] = f.Name
	}
	byVar := map[uintptr]string{}
	for _, f := range flags {
		if rv := reflect.ValueOf(f.Value); rv.Kind() == reflect.Pointer {
			if first, ok := byVar[rv.Pointer()]; ok {
				union(f.Name, first)
			} else {
				byVar[rv.Pointer()] = f.Name
			}
		}
	}
	for _, e := range helpEntries {
		for _, n := range e.names[1:] {
			if _, ok := parent[n]; ok {
				if _, ok := parent[e.names[0]]; ok {
					union(n, e.names[0])
				}
			}
		}
	}
	byRoot := map[string]*option{}
	var opts []*option
	for _, f := range flags {
		root := find(f.Name)
		o := byRoot[root]
		if o == nil {
			b, isBool := f.Value.(interface{ IsBoolFlag() bool })
			o = &option{isBool: isBool && b.IsBoolFlag(), def: f.DefValue}
			o.defOn = o.isBool && f.DefValue == "true"
			o.on = o.defOn
			byRoot[root] = o
			opts = append(opts, o)
		}
		o.names = append(o.names, f.Name)
	}

	for _, o := range opts {
		sort.Slice(o.names, func(i, j int) bool {
			if len(o.names[i]) == 1 != (len(o.names[j]) == 1) {
				return len(o.names[i]) == 1
			}
			return o.names[i] < o.names[j]
		})
		o.section, o.order = otherSection, 1<<20
		for _, n := range o.names {
			if e, ok := help[n]; ok {
				o.section, o.desc, o.hint, o.order = e.section, e.desc, e.hint, e.order
				for _, hn := range e.names { // the help's own long name leads
					if len(hn) > 1 && hasName(o.names, hn) {
						o.primary = hn
						break
					}
				}
				break
			}
		}
		if o.primary == "" {
			o.primary = o.names[len(o.names)-1]
			for _, n := range o.names {
				if len(n) > len(o.primary) {
					o.primary = n
				}
			}
		}
		if o.desc == "" {
			o.desc = "(not described in --help)"
		}
		for _, n := range o.names {
			if strings.Contains(n, "pass") || strings.Contains(n, "jwt-key") {
				o.secret = true
			}
		}
	}
	sort.SliceStable(opts, func(i, j int) bool {
		if opts[i].order != opts[j].order {
			return opts[i].order < opts[j].order
		}
		return opts[i].primary < opts[j].primary
	})
	return opts
}

func hasName(names []string, n string) bool {
	for _, x := range names {
		if x == n {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// builder state: what's ticked, and the command it adds up to

const webSection = "WEBSITES & APPS" // pinned first: this is a website builder

type builder struct {
	opts     []*option
	sections []string // display order
	target   string
	host     bool // website mode: compose `tshare host <dir>` (auto static/app)
	stack    string
}

// newBuilder prefills from a command line, so `tshare --webwiz -p pw ./blog`
// opens with -p ticked and the target set.
func newBuilder(args []string) *builder {
	b := &builder{opts: catalogOptions()}
	seen := map[string]bool{}
	for _, o := range b.opts {
		if !seen[o.section] {
			seen[o.section] = true
			b.sections = append(b.sections, o.section)
		}
	}
	sort.SliceStable(b.sections, func(i, j int) bool {
		rank := func(s string) int {
			switch s {
			case webSection:
				return 0
			case otherSection:
				return 2
			}
			return 1
		}
		return rank(b.sections[i]) < rank(b.sections[j])
	})

	fs := flag.NewFlagSet("webwiz-prefill", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	registerFlags(fs, defaultConfig())
	var clean []string
	for _, a := range args {
		if a != "--webwiz" && a != "-webwiz" {
			clean = append(clean, a)
		}
	}
	if fs.Parse(clean) == nil {
		fs.Visit(func(f *flag.Flag) {
			for _, o := range b.opts {
				if hasName(o.names, f.Name) {
					o.on, o.value = true, f.Value.String()
					if o.isBool && o.value == "false" {
						o.on = false
					}
				}
			}
		})
		if rest := fs.Args(); len(rest) > 0 {
			b.target = rest[0]
		}
	}
	b.setTarget(b.target)
	return b
}

// setTarget re-detects what the target is; a folder defaults to website mode.
func (b *builder) setTarget(t string) {
	b.target, b.stack, b.host = t, "", false
	if t == "" {
		return
	}
	if fi, err := os.Stat(t); err == nil && fi.IsDir() {
		abs, _ := filepath.Abs(t)
		if _, kind := detectStack(abs); kind != "" {
			b.stack, b.host = kind, true
		}
	}
}

func (b *builder) isDirTarget() bool {
	fi, err := os.Stat(b.target)
	return err == nil && fi.IsDir()
}

// argv is the real command, with real values: exactly what `r` runs.
func (b *builder) argv() []string {
	var flags []string
	for _, o := range b.opts {
		switch {
		case o.isBool && o.on != o.defOn:
			if o.on {
				flags = append(flags, o.flag())
			} else {
				flags = append(flags, o.flag()+"=false")
			}
		case !o.isBool && o.on:
			flags = append(flags, o.flag(), o.value)
		}
	}
	if b.host && b.isDirTarget() {
		return append([]string{"host", b.target}, flags...)
	}
	if b.target != "" {
		flags = append(flags, b.target)
	}
	return flags
}

// find returns the option a name (or any alias of it) belongs to.
func (b *builder) find(name string) *option {
	name = strings.TrimLeft(name, "-")
	for _, o := range b.opts {
		if hasName(o.names, name) {
			return o
		}
	}
	return nil
}

// set ticks an option by any of its names: a boolean takes true/false, a
// valued option takes its value ("" unticks it). Used by front ends that
// receive choices as data rather than keystrokes.
func (b *builder) set(name string, v any) error {
	o := b.find(name)
	if o == nil {
		return fmt.Errorf("--%s isn't a tshare option", strings.TrimLeft(name, "-"))
	}
	if strings.HasPrefix(o.primary, "__") || hasName(o.names, "webwiz") || reservedFlags[o.primary] {
		return fmt.Errorf("%s can't be set here", o.flag())
	}
	switch x := v.(type) {
	case bool:
		if !o.isBool {
			return fmt.Errorf("%s needs a value, not true/false", o.flag())
		}
		o.on = x
	case string:
		if o.isBool {
			switch x {
			case "true", "1", "on", "yes":
				o.on = true
			case "false", "0", "off", "no", "":
				o.on = false
			default:
				return fmt.Errorf("%s is on/off, not %q", o.flag(), x)
			}
			return nil
		}
		o.value, o.on = x, x != ""
	case float64: // JSON numbers
		if o.isBool {
			return fmt.Errorf("%s is on/off", o.flag())
		}
		o.value, o.on = strconv.FormatFloat(x, 'f', -1, 64), true
	default:
		return fmt.Errorf("%s: unsupported value %v", o.flag(), v)
	}
	return nil
}

// needsNoTarget: some shares take no path (-u inbox, --hub, --room, --call…).
func (b *builder) needsNoTarget() bool {
	for _, name := range []string{"upload", "hub", "room", "call", "blackhole", "kuma", "dashboard"} {
		if o := b.find(name); o != nil && o.on {
			return true
		}
	}
	return false
}

// commandLine renders argv for a shell, masking secrets when asked.
func (b *builder) commandLine(mask bool) string {
	argv := b.argv()
	parts := []string{"tshare"}
	for i, a := range argv {
		if mask && i > 0 && b.isSecretFlag(argv[i-1]) {
			a = "••••••"
		} else if a == "" || strings.ContainsAny(a, " \t'\"$`\\!*?[]{}()<>|&;#~") {
			a = shQuote(a)
		}
		parts = append(parts, a)
	}
	return strings.Join(parts, " ")
}

func (b *builder) isSecretFlag(tok string) bool {
	name := flagName(tok)
	for _, o := range b.opts {
		if o.secret && !o.isBool && hasName(o.names, name) {
			return true
		}
	}
	return false
}

// selected counts options changed from their defaults.
func (b *builder) selected() int {
	n := 0
	for _, o := range b.opts {
		if o.on != o.defOn {
			n++
		}
	}
	return n
}
