//go:build unix && !nowebwiz

package main

// --webwiz: an interactive checklist of every tshare option, grouped and
// explained, that composes the command as you tick and then runs it.
//
// Nothing here is a second copy of the options. Rows come from registerFlags
// (aliases folded together by the variable they set); explanations and
// sections come from the --help text. So a flag can't be missing from the
// builder, and its explanation can't drift from --help. Stdlib only: the
// terminal goes raw via stty, and without a terminal the same checklist is
// printed as plain text instead.

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

func init() { register(func(args []string) { runWebwiz(args) }, "webwiz", "wiz") }

// ---------------------------------------------------------------------------
// no terminal: print the whole checklist as text

func (b *builder) printChecklist(out io.Writer) {
	fmt.Fprintf(out, "tshare --webwiz — every option, explained (%d)\n", len(b.opts))
	fmt.Fprintln(out, "Run it in a terminal for the interactive checklist.")
	for _, sec := range b.sections {
		fmt.Fprintf(out, "\n%s\n", sec)
		for _, o := range b.opts {
			if o.section != sec {
				continue
			}
			box := "[ ]"
			if o.on {
				box = "[x]"
			}
			head := o.label()
			if o.hint != "" {
				head += " " + o.hint
			}
			fmt.Fprintf(out, "  %s %s\n", box, head)
			for _, l := range wrapText(o.desc, 72) {
				fmt.Fprintf(out, "        %s\n", l)
			}
		}
	}
	fmt.Fprintf(out, "\n$ %s\n", b.commandLine(true))
}

// ---------------------------------------------------------------------------
// the interactive checklist

type wizRow struct {
	kind string // "target", "mode", "section", "opt"
	opt  *option
	sec  string
}

type wizUI struct {
	*builder
	cursor, scroll int
	filter         string
	mode           string // "", "filter", "edit"
	editBuf        string
	editTarget     bool
	status         string
	color          bool
}

func runWebwiz(args []string) {
	b := newBuilder(args)
	if !isatty(os.Stdin) || !isatty(os.Stdout) {
		b.printChecklist(os.Stdout)
		return
	}
	ui := &wizUI{builder: b, color: os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"}
	action, err := ui.run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tshare --webwiz: %v\n", err)
		b.printChecklist(os.Stdout)
		os.Exit(1)
	}
	switch action {
	case "run":
		argv := b.argv()
		fmt.Printf("$ %s\n", b.commandLine(true))
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintf(os.Stderr, "tshare: %v\n", err)
			os.Exit(1)
		}
		err = syscall.Exec(exe, append([]string{"tshare"}, argv...), os.Environ())
		fmt.Fprintf(os.Stderr, "tshare: could not start: %v\n", err)
		os.Exit(1)
	case "print":
		fmt.Println(b.commandLine(false))
	}
}

func stty(args ...string) (string, error) {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = os.Stdin
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

func termSize() (rows, cols int) {
	var ws struct{ Row, Col, X, Y uint16 }
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws)))
	if e != 0 || ws.Row == 0 || ws.Col == 0 {
		return 24, 80
	}
	return int(ws.Row), int(ws.Col)
}

// run owns the terminal until the user runs, prints or quits; it always puts
// the terminal back, even on a signal.
func (u *wizUI) run() (action string, err error) {
	saved, err := stty("-g")
	if err != nil {
		return "", fmt.Errorf("can't read terminal settings: %w", err)
	}
	if _, err := stty("raw", "-echo"); err != nil {
		return "", fmt.Errorf("can't switch the terminal to raw mode: %w", err)
	}
	os.Stdout.WriteString("\x1b[?1049h\x1b[?25l")
	restore := func() {
		os.Stdout.WriteString("\x1b[?25h\x1b[?1049l")
		stty(saved)
	}
	defer restore()

	keys := make(chan string, 16)
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				close(keys)
				return
			}
			keys <- string(buf[:n])
		}
	}()
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGWINCH, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigs)

	u.render()
	for {
		select {
		case sig := <-sigs:
			if sig != syscall.SIGWINCH {
				return "quit", nil
			}
		case chunk, ok := <-keys:
			if !ok {
				return "quit", nil
			}
			for _, k := range splitKeys(chunk) {
				if a := u.handle(k); a != "" {
					return a, nil
				}
			}
		}
		u.render()
	}
}

// splitKeys breaks one read into keys: CSI/SS3 escape sequences stay whole.
func splitKeys(s string) []string {
	var keys []string
	for len(s) > 0 {
		if s[0] == 0x1b && len(s) > 1 && (s[1] == '[' || s[1] == 'O') {
			i := 2
			for i < len(s) && (s[i] < 0x40 || s[i] > 0x7e) {
				i++
			}
			if i < len(s) {
				i++
			}
			keys = append(keys, s[:i])
			s = s[i:]
			continue
		}
		_, size := utf8.DecodeRuneInString(s)
		keys = append(keys, s[:size])
		s = s[size:]
	}
	return keys
}

func (u *wizUI) rows() []wizRow {
	rows := []wizRow{{kind: "target"}}
	if u.isDirTarget() {
		rows = append(rows, wizRow{kind: "mode"})
	}
	f := strings.ToLower(u.filter)
	for _, sec := range u.sections {
		var group []wizRow
		for _, o := range u.opts {
			if o.section != sec {
				continue
			}
			if f != "" && !strings.Contains(strings.ToLower(strings.Join(o.names, " ")+" "+o.desc), f) {
				continue
			}
			group = append(group, wizRow{kind: "opt", opt: o})
		}
		if len(group) > 0 {
			rows = append(rows, wizRow{kind: "section", sec: sec})
			rows = append(rows, group...)
		}
	}
	return rows
}

// selectable lists the row indexes the cursor can land on (not headings).
func selectable(rows []wizRow) []int {
	var idx []int
	for i, r := range rows {
		if r.kind != "section" {
			idx = append(idx, i)
		}
	}
	return idx
}

func (u *wizUI) current() wizRow {
	rows := u.rows()
	sel := selectable(rows)
	if len(sel) == 0 {
		return wizRow{}
	}
	if u.cursor >= len(sel) {
		u.cursor = len(sel) - 1
	}
	if u.cursor < 0 {
		u.cursor = 0
	}
	return rows[sel[u.cursor]]
}

func (u *wizUI) handle(k string) string {
	switch u.mode {
	case "edit", "filter":
		return u.handleText(k)
	}
	u.status = ""
	sel := len(selectable(u.rows()))
	switch k {
	case "\x1b[A", "k":
		u.cursor--
	case "\x1b[B", "j":
		u.cursor++
	case "\x1b[5~":
		u.cursor -= 10
	case "\x1b[6~":
		u.cursor += 10
	case "g", "\x1b[H", "\x1bOH":
		u.cursor = 0
	case "G", "\x1b[F", "\x1bOF":
		u.cursor = sel - 1
	case "\t":
		u.nextSection(1)
	case "\x1b[Z":
		u.nextSection(-1)
	case " ":
		u.toggle(false)
	case "\r", "\n":
		u.toggle(true)
	case "/":
		u.mode, u.editBuf = "filter", u.filter
	case "x":
		for _, o := range u.opts {
			o.on, o.value = o.defOn, ""
		}
		u.status = "reset every option to its default"
	case "c":
		if copyClipboard(u.commandLine(false)) {
			u.status = "✓ copied the command to the clipboard"
		} else {
			u.status = "clipboard unavailable (pbcopy / wl-copy / xclip)"
		}
	case "r":
		if u.target == "" && !u.needsNoTarget() {
			u.status = "set a TARGET first (the folder, file or URL to share) — or tick a mode that needs none"
			return ""
		}
		return "run"
	case "p":
		return "print"
	case "q", "\x1b", "\x03", "\x04":
		return "quit"
	}
	if u.cursor < 0 {
		u.cursor = 0
	}
	if u.cursor >= sel {
		u.cursor = sel - 1
	}
	return ""
}

func (u *wizUI) nextSection(dir int) {
	rows := u.rows()
	sel := selectable(rows)
	if len(sel) == 0 {
		return
	}
	cur := rows[sel[u.cursor]]
	for i := u.cursor + dir; i >= 0 && i < len(sel); i += dir {
		r := rows[sel[i]]
		if r.kind == "opt" && (cur.kind != "opt" || r.opt.section != cur.opt.section) {
			// land on the FIRST option of that section
			for i > 0 && dir < 0 && rows[sel[i-1]].kind == "opt" && rows[sel[i-1]].opt.section == r.opt.section {
				i--
			}
			u.cursor = i
			return
		}
	}
}

func (u *wizUI) toggle(enter bool) {
	r := u.current()
	switch r.kind {
	case "target":
		u.mode, u.editBuf, u.editTarget = "edit", u.target, true
	case "mode":
		u.host = !u.host
	case "opt":
		o := r.opt
		switch {
		case o.isBool:
			o.on = !o.on
		case o.on && !enter:
			o.on = false
		default:
			u.mode, u.editTarget = "edit", false
			u.editBuf = o.value
			if u.editBuf == "" && o.def != "" && o.def != "0" {
				u.editBuf = o.def
			}
		}
	}
}

func (u *wizUI) handleText(k string) string {
	switch k {
	case "\r", "\n":
		u.commitText()
	case "\x1b", "\x03":
		if u.mode == "filter" {
			u.filter = ""
		}
		u.mode = ""
	case "\x7f", "\b":
		if _, size := utf8.DecodeLastRuneInString(u.editBuf); size > 0 {
			u.editBuf = u.editBuf[:len(u.editBuf)-size]
		}
	case "\x15": // Ctrl-U
		u.editBuf = ""
	default:
		if r, _ := utf8.DecodeRuneInString(k); len(k) > 0 && unicode.IsPrint(r) && !strings.HasPrefix(k, "\x1b") {
			u.editBuf += k
		}
	}
	if u.mode == "filter" {
		u.filter, u.cursor = u.editBuf, 0
	}
	return ""
}

func (u *wizUI) commitText() {
	switch {
	case u.mode == "filter":
		u.filter = u.editBuf
	case u.editTarget:
		u.setTarget(strings.TrimSpace(u.editBuf))
	default:
		if r := u.current(); r.kind == "opt" {
			r.opt.value = u.editBuf
			r.opt.on = u.editBuf != ""
		}
	}
	u.mode = ""
}

// ---------------------------------------------------------------------------
// drawing

func (u *wizUI) c(code, s string) string {
	if !u.color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (u *wizUI) render() {
	height, width := termSize()
	if width < 40 {
		width = 40
	}
	var b strings.Builder
	line := func(s string) {
		b.WriteString(fit(s, width))
		b.WriteString("\x1b[K\r\n")
	}
	rule := u.c("2", strings.Repeat("─", width))

	title := u.c("1;36", " tshare webwiz") + u.c("2", fmt.Sprintf("  %d options · %d ticked", len(u.opts), u.selected()))
	if u.filter != "" {
		title += u.c("33", "  filter: "+u.filter)
	}
	line(title)
	line(u.c("2", " ↑↓ move  space tick  ⏎ edit  tab section  / filter  r run  c copy  p print  x reset  q quit"))
	line(rule)

	rows := u.rows()
	sel := selectable(rows)
	if u.cursor >= len(sel) {
		u.cursor = len(sel) - 1
	}
	if u.cursor < 0 {
		u.cursor = 0
	}
	curRow := -1
	if len(sel) > 0 {
		curRow = sel[u.cursor]
	}

	const detailH = 6
	listH := height - 3 - 1 - detailH - 3
	if listH < 3 {
		listH = 3
	}
	if curRow < u.scroll+1 { // keep a heading above the cursor visible
		u.scroll = curRow - 1
	}
	if curRow >= u.scroll+listH {
		u.scroll = curRow - listH + 1
	}
	if u.scroll < 0 {
		u.scroll = 0
	}
	for i := u.scroll; i < u.scroll+listH; i++ {
		if i >= len(rows) {
			line("")
			continue
		}
		line(u.rowText(rows[i], i == curRow, width))
	}

	line(rule)
	detail := u.detail(rows, curRow, width)
	for i := 0; i < detailH; i++ {
		if i < len(detail) {
			line(detail[i])
		} else {
			line("")
		}
	}
	line(rule)
	switch {
	case u.mode == "edit":
		what := "value"
		if u.editTarget {
			what = "target (folder, file or URL)"
		} else if r := u.current(); r.kind == "opt" {
			what = r.opt.flag()
		}
		shown := u.editBuf
		if r := u.current(); !u.editTarget && r.kind == "opt" && r.opt.secret {
			shown = strings.Repeat("•", utf8.RuneCountInString(shown))
		}
		line(u.c("1;33", " "+what+": ") + shown + u.c("7", " ") + u.c("2", "   ⏎ ok · esc cancel"))
	case u.mode == "filter":
		line(u.c("1;33", " / ") + u.editBuf + u.c("7", " ") + u.c("2", "   ⏎ keep · esc clear"))
	default:
		line(u.c("1;32", " $ ") + u.commandLine(true))
	}
	if u.status != "" {
		line(" " + u.c("33", u.status))
	} else {
		line("")
	}
	b.WriteString("\x1b[J")
	os.Stdout.WriteString("\x1b[H" + b.String())
}

func (u *wizUI) rowText(r wizRow, cur bool, width int) string {
	pointer := "  "
	if cur {
		pointer = u.c("1;36", "› ")
	}
	switch r.kind {
	case "section":
		return u.c("1;35", " "+r.sec)
	case "target":
		t := u.target
		if t == "" {
			t = u.c("2", "(none — ⏎ to set the folder, file or URL to share)")
		}
		return pointer + u.c("1", "TARGET   ") + t
	case "mode":
		box := u.box(u.host)
		what := "website mode — tshare host: serves it as a site, or runs it as an app"
		if u.stack != "" {
			what += " (detected: " + u.stack + ")"
		}
		return pointer + box + " " + what
	}
	o := r.opt
	name := o.label()
	if !o.isBool {
		if o.on {
			v := o.value
			if o.secret {
				v = "••••••"
			}
			name += " " + u.c("33", v)
		} else if o.hint != "" {
			name += " " + u.c("2", o.hint)
		}
	}
	const col = 34
	pad := col - displayWidth(stripANSI(name))
	if pad < 2 {
		pad = 2
	}
	return pointer + u.box(o.on) + " " + name + strings.Repeat(" ", pad) + u.c("2", o.desc)
}

func (u *wizUI) box(on bool) string {
	if on {
		return u.c("1;32", "[✓]")
	}
	return u.c("2", "[ ]")
}

func (u *wizUI) detail(rows []wizRow, cur, width int) []string {
	if cur < 0 || cur >= len(rows) {
		return nil
	}
	w := width - 4
	var out []string
	add := func(head, body string) {
		out = append(out, " "+u.c("1", head))
		for _, l := range wrapText(body, w) {
			out = append(out, "   "+l)
		}
	}
	switch r := rows[cur]; r.kind {
	case "target":
		add("TARGET", "What to share: a folder (a website or app is detected automatically), a "+
			"file, a URL to download, or - for stdin. Leave it empty for modes that need "+
			"no path, like -u (inbox), --hub, --room or --call.")
	case "mode":
		add("website mode", "Compose `tshare host <folder>`: tshare looks at the folder and either "+
			"serves it as a website (index.html) or starts it as an app (package.json, a .js "+
			"server, app.py, index.php, compose.yml) and publishes that. Untick to share the "+
			"folder as files instead.")
	case "opt":
		o := r.opt
		head := o.label()
		if o.hint != "" {
			head += " " + o.hint
		}
		body := o.desc
		switch {
		case o.defOn:
			body += " (on by default)"
		case !o.isBool && o.def != "" && o.def != "0" && !o.secret:
			body += " (default: " + o.def + ")"
		}
		add(head+u.c("2", "   · "+strings.ToLower(o.section)), body)
	}
	return out
}

// ---------------------------------------------------------------------------
// text helpers

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]")

func stripANSI(s string) string { return ansiRe.ReplaceAllString(s, "") }

// displayWidth counts terminal columns, treating wide/emoji runes as two.
func displayWidth(s string) int {
	n := 0
	for _, r := range s {
		switch {
		case r == 0x200d || unicode.Is(unicode.Mn, r) || r == 0xfe0f:
		case r >= 0x1100 && (r <= 0x115f || r >= 0x2e80 && r <= 0xa4cf || r >= 0xac00 && r <= 0xd7a3 ||
			r >= 0xf900 && r <= 0xfaff || r >= 0xfe30 && r <= 0xfe4f || r >= 0xff00 && r <= 0xff60 ||
			r >= 0xffe0 && r <= 0xffe6 || r >= 0x1f300 && r <= 0x1faff || r >= 0x26a1 && r <= 0x26a1):
			n += 2
		default:
			n++
		}
	}
	return n
}

// fit truncates a (possibly coloured) line to width columns, keeping escapes.
func fit(s string, width int) string {
	if displayWidth(stripANSI(s)) <= width {
		return s
	}
	var b strings.Builder
	cols := 0
	for i := 0; i < len(s); {
		if loc := ansiRe.FindStringIndex(s[i:]); loc != nil && loc[0] == 0 {
			b.WriteString(s[i : i+loc[1]])
			i += loc[1]
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		w := displayWidth(string(r))
		if cols+w > width-1 {
			b.WriteString("…\x1b[0m")
			break
		}
		b.WriteRune(r)
		cols += w
		i += size
	}
	return b.String()
}

func wrapText(s string, width int) []string {
	if width < 20 {
		width = 20
	}
	var lines []string
	cur := ""
	for _, word := range strings.Fields(s) {
		if cur != "" && displayWidth(cur)+1+displayWidth(word) > width {
			lines = append(lines, cur)
			cur = word
			continue
		}
		if cur == "" {
			cur = word
		} else {
			cur += " " + word
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}
