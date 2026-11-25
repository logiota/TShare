//go:build unix && !notui

package main

// `tshare tui`: everything at a glance in the terminal, by keyboard or mouse.
//
//   - every running share on one line: an emoji for each address it answers on
//     (click one to copy that link), its expiry, and open / QR / stop;
//   - a new share built by ticking boxes: the target, the options people reach
//     for, and — expanded — every option tshare has, each explained;
//   - the dashboard and the reboot-restore agent as switches in the header.
//
// `tshare --webwiz` opens the same screen with the full option list expanded.
//
// A frame is rows of cells placed at explicit columns. A cell with an id is a
// widget: keyboard focus, mouse hit-testing and drawing all read that one
// list, so they can't disagree about what is where — and because every cell
// is positioned on its own, an emoji a terminal draws wider or narrower than
// expected can't shift the click targets after it.
//
// Stdlib only (raw mode via stty). Shares it starts are detached `tshare -b`
// processes, so quitting takes nothing down. Without a terminal it prints the
// same information as text. Optional — build with -tags notui to leave it out.

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"
)

func init() {
	register(func(args []string) { runTUI(args, false) }, "tui", "ui")
	register(func(args []string) { runTUI(args, true) }, "webwiz", "wiz")
}

func runTUI(args []string, wizard bool) {
	b := newBuilder(args)
	if !isatty(os.Stdin) || !isatty(os.Stdout) {
		if wizard {
			b.printChecklist(os.Stdout)
		} else {
			printGlance(os.Stdout)
		}
		return
	}
	u := newTUI(b, wizard)
	action, err := u.run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tshare tui: %v\n", err)
		os.Exit(1)
	}
	switch action {
	case "run": // in this terminal, in the foreground: become the share
		fmt.Printf("$ %s\n", b.commandLine(true))
		exe, err := os.Executable()
		if err == nil {
			err = syscall.Exec(exe, append([]string{"tshare"}, b.argv()...), os.Environ())
		}
		fmt.Fprintf(os.Stderr, "tshare: could not start: %v\n", err)
		os.Exit(1)
	case "print":
		fmt.Println(b.commandLine(false))
	}
}

// ---------------------------------------------------------------------------
// no terminal: the same information as text

// printGlance lists the running shares with every link each answers on.
func printGlance(out io.Writer) {
	shares := liveShares()
	if len(shares) == 0 {
		fmt.Fprintln(out, "tshare — nothing shared right now")
	} else {
		fmt.Fprintf(out, "tshare — %d running\n", len(shares))
	}
	for _, r := range shares {
		fmt.Fprintf(out, "\n%s (%s, %s) · id %s\n", dashName(r), r.Mode, expiryText(r), r.ID)
		for _, l := range shareLinks(r) {
			fmt.Fprintf(out, "  %s %-9s %s\n", l.Icon, l.Label, l.URL)
		}
	}
	fmt.Fprintln(out, "\nRun `tshare tui` in a terminal for the interactive view.")
}

// printChecklist lists every option, explained, and the command it adds up to.
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

func expiryText(r stateRec) string {
	if r.Expires.IsZero() {
		return "never expires"
	}
	return humanDur(time.Until(r.Expires)) + " left"
}

// ---------------------------------------------------------------------------
// the frame: rows of cells; a cell with an id is a widget

type cell struct {
	text string // what's drawn (may carry colour)
	w    int    // columns it occupies; the next cell starts w columns on
	id   string // widget id; "" for decoration
	act  func() // a click, or space
	alt  func() // enter, when that differs (type a value instead of toggling)
	hint string // shown in the footer while it has focus
}

type row []cell

func rowWidth(cells []cell) int {
	n := 0
	for _, c := range cells {
		n += c.w
	}
	return n
}

// spread puts left cells at the left edge and right cells at the right one.
func spread(width int, left, right []cell) row {
	gap := width - rowWidth(left) - rowWidth(right)
	if gap < 0 {
		gap = 0
	}
	return append(append(append(row{}, left...), cell{w: gap}), right...)
}

// placed is a widget with where the last frame put it.
type placed struct {
	cell
	region int // 0 header, 1 body (scrolls), 2 footer
	line   int // within its region
	x      int // first column, 1-based
}

const (
	tuiFootRows = 6
	tuiMinW     = 60
	tuiMinH     = 14
)

type tui struct {
	*builder
	wizard bool
	shares []stateRec
	dash   dashboardCtl
	dashOn bool
	dashAt stateRec
	dashPW string

	focus  string // id of the widget with keyboard focus
	scroll int    // first visible body line
	expand bool   // the full option list is shown
	filter string

	mode     string // "", "edit", "filter", "confirm", "overlay"
	editID   string // what's being typed: "target" or an option name
	editBuf  string
	prompt   string
	yes      func()
	overlay  []string
	pasting  bool
	pasteBuf string

	status string
	busy   string
	action string // set to leave the loop: "run", "print", "quit"
	post   chan func()

	color bool
	osc52 bool // copy through the terminal (OSC 52): the only way over SSH

	// seams, so a test can drive it without a terminal or a clipboard
	out    io.Writer
	size   func() (rows, cols int)
	copyFn func(text string) bool
	openFn func(link string)

	// the last frame: what is where
	W, H             int
	head, body, foot []row
	widgets          []placed
}

func newTUI(b *builder, wizard bool) *tui {
	u := &tui{builder: b, wizard: wizard, expand: wizard, focus: "target",
		post:  make(chan func(), 16),
		color: os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb",
		osc52: os.Getenv("SSH_TTY") != "" || os.Getenv("SSH_CONNECTION") != "",
		out:   os.Stdout, size: termSize, copyFn: copyClipboard, openFn: openBrowser}
	return u
}

func (u *tui) reload() {
	u.shares = u.shares[:0]
	for _, r := range liveShares() {
		if r.Mode != "dashboard" {
			u.shares = append(u.shares, r)
		}
	}
	u.dashAt, u.dashPW, u.dashOn = u.dash.running()
}

// ---------------------------------------------------------------------------
// cells

func (u *tui) c(code, s string) string {
	if !u.color || code == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (u *tui) text(style, s string) cell { return cell{text: u.c(style, s), w: displayWidth(s)} }

func (u *tui) textW(style, s string, w int) cell { return cell{text: u.c(style, fitW(s, w)), w: w} }

// widget is a cell you can focus and activate. The focused one is drawn in
// reverse video — an attribute, not a colour, so it shows under NO_COLOR too.
func (u *tui) widget(id, style, s string, w int, hint string, act, alt func()) cell {
	t := fitW(s, w)
	if id == u.focus {
		t = "\x1b[7m" + t + "\x1b[27m"
	} else {
		t = u.c(style, t)
	}
	return cell{text: t, w: w, id: id, act: act, alt: alt, hint: hint}
}

func tickBox(on bool) string {
	if on {
		return "[✓]"
	}
	return "[ ]"
}

func onStyle(on bool) string {
	if on {
		return "1"
	}
	return ""
}

// tuiQuick are the options most people want, kept in view above the full list.
var tuiQuick = []struct{ name, label string }{
	{"persist", "survive reboots"}, {"password", "password"}, {"expires", "expires"},
	{"root", "publish at the root"}, {"tailnet", "tailnet only"}, {"local", "local network only"},
	{"allow-upload", "visitors can upload"}, {"once", "one download"},
}

var expiryPresets = []string{"", "1h", "1d", "1w", "30d", "never"}

func (u *tui) shown(o *option) string {
	if o.secret {
		return "••••••"
	}
	return o.value
}

// ---------------------------------------------------------------------------
// building a frame

func (u *tui) buildHead() []row {
	left := []cell{u.text("1;36", " tshare"), u.text("2", "  v"+version)}
	var right []cell
	if loginAgent != nil && runtime.GOOS == "darwin" {
		on := loginAgent.Installed()
		right = append(right, u.widget("agent", onStyle(on), tickBox(on)+" restore after reboot", 24,
			"A login agent that brings --persist shares back after a reboot, on the same links.",
			u.toggleAgent, nil), u.text("", "  "))
	}
	right = append(right, u.widget("dash", onStyle(u.dashOn), tickBox(u.dashOn)+" dashboard", 13,
		"A web page tiling all your shares, on its own password-protected link.", u.toggleDash, nil))
	if u.dashOn {
		right = append(right, u.text("", " "), u.widget("dash:link", "", "📋", 3,
			"copy the dashboard link · "+u.dashAt.URL, func() { u.copy(u.dashAt.URL, "dashboard link") }, nil))
		if u.dashPW != "" {
			right = append(right, u.widget("dash:pw", "", "🔑", 3,
				"copy the dashboard password · "+u.dashPW, func() { u.copy(u.dashPW, "dashboard password") }, nil))
		}
	}
	right = append(right, u.text("", " "))
	return []row{spread(u.W, left, right), {u.text("2", strings.Repeat("─", u.W))}}
}

func (u *tui) buildBody() []row {
	W := u.W
	rows := []row{spread(W,
		[]cell{u.text("1;35", " SHARES"), u.text("2", fmt.Sprintf(" · %d running", len(u.shares)))},
		[]cell{u.text("2", "click an emoji to copy that link ")})}
	for _, r := range u.shares {
		rows = append(rows, u.shareRow(r))
	}
	if len(u.shares) == 0 {
		rows = append(rows, row{u.text("2", "   nothing shared yet — set a target below, then press s")})
	}

	rows = append(rows, row{}, row{u.text("1;35", " NEW SHARE")})
	var mode []cell
	if u.isDirTarget() {
		label := tickBox(u.host) + " website mode"
		if u.stack != "" {
			label += " (" + u.stack + ")"
		}
		mode = []cell{u.widget("host", onStyle(u.host), label, displayWidth(label),
			"Serve the folder as a website, or run it as an app if it is one (tshare host). Untick to share it as files.",
			func() { u.host = !u.host }, nil), u.text("", " ")}
	}
	tv, style := u.target, ""
	if tv == "" {
		tv, style = "⏎ to type a file, folder or URL — or drop one onto this window", "2"
	}
	tw := W - rowWidth(mode) - 4
	rows = append(rows, spread(W, []cell{u.text("", "  "), u.widget("target", style, "target  "+tv, tw,
		"What to share: a file, a folder (a website or app in it is detected), a URL to download — or nothing, for -u, --hub, --room, --call.",
		u.editTarget, nil)}, mode))
	rows = append(rows, u.flow(u.quickCells(), 2)...)

	arrow := "▸"
	if u.expand {
		arrow = "▾"
	}
	all := []cell{u.text("", "  "), u.widget("all", "", fmt.Sprintf("%s all %d options", arrow, len(u.visibleOpts(""))), 22,
		"Show every option tshare has, each explained.", func() { u.expand = !u.expand }, nil)}
	var filt []cell
	if u.expand {
		label := "/ filter"
		if u.filter != "" {
			label = "/ " + u.filter
		}
		filt = []cell{u.widget("filter", "33", label, max(12, displayWidth(label)),
			"Type to narrow the option list.", u.editFilter, nil), u.text("", " ")}
	}
	rows = append(rows, spread(W, all, filt))
	if !u.expand {
		return rows
	}
	section := ""
	for _, o := range u.visibleOpts(u.filter) {
		if o.section != section {
			section = o.section
			rows = append(rows, row{u.text("35", "   "+section)})
		}
		name := o.label()
		switch {
		case o.isBool:
		case o.on:
			name += " " + u.shown(o)
		case o.hint != "":
			name += " " + o.hint
		}
		hint := o.desc
		switch {
		case o.defOn:
			hint += " (on by default)"
		case !o.isBool && o.def != "" && o.def != "0" && !o.secret:
			hint += " (default: " + o.def + ")"
		}
		const nameW = 38
		rows = append(rows, row{u.text("", "   "),
			u.widget("o:"+o.primary, onStyle(o.on), tickBox(o.on)+" "+name, nameW, hint,
				func() { u.toggleOpt(o) }, func() { u.enterOpt(o) }),
			u.textW("2", " "+o.desc, max(0, W-nameW-4))})
	}
	return rows
}

// visibleOpts are the options the screen offers: all but the ones a launch
// sets itself, narrowed by the filter.
func (u *tui) visibleOpts(filter string) []*option {
	f := strings.ToLower(filter)
	var out []*option
	for _, sec := range u.sections {
		for _, o := range u.opts {
			if o.section != sec || reservedFlags[o.primary] {
				continue
			}
			if f == "" || strings.Contains(strings.ToLower(strings.Join(o.names, " ")+" "+o.desc), f) {
				out = append(out, o)
			}
		}
	}
	return out
}

func (u *tui) shareRow(r stateRec) row {
	id := "s:" + r.ID
	left := []cell{u.text("", " ")}
	for i, l := range shareLinks(r) {
		left = append(left, u.widget(id+":"+strconv.Itoa(i), "", l.Icon, 3,
			"copy the "+l.Label+" · "+l.URL, func() { u.copy(l.URL, l.Label) }, nil))
	}
	left = append(left, u.textW("1", " "+dashName(r), 22))

	var right []cell
	if r.Password {
		right = append(right, cell{text: "🔒", w: 3})
	}
	if isPersisted(r.ID) {
		right = append(right, cell{text: "🔁", w: 3})
	}
	when := "never"
	if !r.Expires.IsZero() {
		when = humanDur(time.Until(r.Expires)) + " left"
	}
	if r.Downloads > 0 {
		when += fmt.Sprintf(" · %d↓", r.Downloads)
	}
	right = append(right, u.textW("2", when, 17),
		u.widget(id+":open", "", "[open]", 6, "open it in your browser · "+r.URL, func() { u.open(r.URL) }, nil), u.text("", " "),
		u.widget(id+":qr", "", "[qr]", 4, "show a QR code for the link", func() { u.showQR(r) }, nil), u.text("", " "),
		u.widget(id+":stop", "31", "[stop]", 6, "stop sharing — the link stops working", func() { u.askStop(r) }, nil), u.text("", " "))
	if urlW := u.W - rowWidth(left) - rowWidth(right) - 1; urlW >= 14 {
		left = append(left, u.widget(id+":url", "36", midTrunc(r.URL, urlW), urlW,
			"copy the link · "+r.URL, func() { u.copy(r.URL, "link") }, nil))
	}
	return spread(u.W, left, right)
}

func (u *tui) quickCells() []cell {
	var cells []cell
	for _, q := range tuiQuick {
		o := u.find(q.name)
		if o == nil {
			continue
		}
		id := "q:" + q.name
		switch {
		case q.name == "expires":
			v := "default"
			if o.on {
				v = o.value
			}
			label := "expires: " + v + " ▾"
			cells = append(cells, u.widget(id, onStyle(o.on), label, max(18, displayWidth(label)),
				o.desc+" Space steps through common choices; ⏎ types one.",
				func() { u.cycleExpiry(o) }, func() { u.editOpt(o) }))
		case o.isBool:
			label := tickBox(o.on) + " " + q.label
			cells = append(cells, u.widget(id, onStyle(o.on), label, displayWidth(label), o.desc,
				func() { o.on = !o.on }, nil))
		default:
			label := tickBox(o.on) + " " + q.label
			if o.on {
				label += " " + u.shown(o)
			}
			cells = append(cells, u.widget(id, onStyle(o.on), label, displayWidth(label), o.desc,
				func() { u.toggleOpt(o) }, func() { u.enterOpt(o) }))
		}
	}
	return cells
}

// flow lays cells out left to right, wrapping to as many rows as they need.
func (u *tui) flow(cells []cell, indent int) []row {
	var rows []row
	cur := row{u.text("", strings.Repeat(" ", indent))}
	for _, c := range cells {
		if len(cur) > 1 && rowWidth(cur)+c.w+3 > u.W {
			rows = append(rows, cur)
			cur = row{u.text("", strings.Repeat(" ", indent))}
		}
		cur = append(cur, c, u.text("", "   "))
	}
	return append(rows, cur)
}

func (u *tui) buildFoot(bodyH int) []row {
	W := u.W
	rule := row{u.text("2", strings.Repeat("─", W))}
	if len(u.body) > bodyH {
		note := fmt.Sprintf(" %d–%d of %d · scroll for more ", u.scroll+1, min(u.scroll+bodyH, len(u.body)), len(u.body))
		rule = spread(W, []cell{u.text("2", strings.Repeat("─", max(0, W-displayWidth(note)-2)))},
			[]cell{u.text("2", note), u.text("2", "──")})
	}
	buttons := []cell{
		u.widget("share", "1;32", "[ Share ]", 9, "Start this share in the background; it appears in the list above.", u.share, nil), u.text("", " "),
		u.widget("runhere", "", "[run here]", 10, "Quit this screen and run the share in this terminal, in the foreground.", func() { u.action = "run" }, nil), u.text("", " "),
		u.widget("copycmd", "", "[copy cmd]", 10, "Copy the command line, to paste or script it.", func() { u.copy(u.commandLine(false), "command") }, nil), u.text("", " "),
	}
	cmd := spread(W, []cell{u.text("1;32", " $ "), u.textW("", u.commandLine(true), max(0, W-rowWidth(buttons)-4))}, buttons)

	var line row
	switch {
	case u.mode == "edit":
		what, shown := "target (a file, folder or URL)", u.editBuf
		if o := u.find(u.editID); u.editID != "target" && o != nil {
			what = o.flag()
			if o.secret {
				shown = strings.Repeat("•", utf8.RuneCountInString(shown))
			}
		}
		line = row{u.text("1;33", " "+what+": "), u.text("", shown), u.text("7", " "), u.text("2", "   ⏎ ok · esc cancel")}
	case u.mode == "filter":
		line = row{u.text("1;33", " / "), u.text("", u.editBuf), u.text("7", " "), u.text("2", "   ⏎ keep · esc clear")}
	case u.mode == "confirm":
		line = row{u.text("1;33", " "+u.prompt)}
	case u.busy != "":
		line = row{u.text("33", " ⏳ "+u.busy)}
	default:
		line = row{u.textW("", " "+u.status, W)}
	}
	keys := " ↑↓←→ move · space tick · ⏎ type/do · s share · / filter · a agent · d dashboard · ? help · q quit"
	return []row{rule, {}, {}, cmd, line, {u.textW("2", keys, W)}}
}

// layout builds the frame for the current state and terminal size, and
// records where every widget landed.
func (u *tui) layout() {
	u.H, u.W = u.size()
	for pass := 0; pass < 2; pass++ {
		u.head, u.body = u.buildHead(), u.buildBody()
		bodyH := u.bodyH()
		if u.scroll > len(u.body)-bodyH {
			u.scroll = len(u.body) - bodyH
		}
		if u.scroll < 0 {
			u.scroll = 0
		}
		u.foot = u.buildFoot(bodyH)
		u.widgets = u.widgets[:0]
		for region, rows := range [][]row{u.head, u.body, u.foot} {
			for li, r := range rows {
				x := 1
				for _, c := range r {
					if c.id != "" {
						u.widgets = append(u.widgets, placed{c, region, li, x})
					}
					x += c.w
				}
			}
		}
		if u.index(u.focus) >= 0 || len(u.widgets) == 0 {
			break
		}
		u.focus = "target" // the focused widget is gone (a share stopped): fall back, redraw
	}
	if i := u.index(u.focus); i >= 0 {
		for n, l := range wrapText(u.widgets[i].hint, u.W-4) {
			if n < 2 {
				u.foot[1+n] = row{u.text("2", "  "+l)}
			}
		}
	}
}

func (u *tui) bodyH() int { return max(1, u.H-len(u.head)-tuiFootRows) }

func (u *tui) index(id string) int {
	for i := range u.widgets {
		if u.widgets[i].id == id {
			return i
		}
	}
	return -1
}

// vy is a widget's line in the whole document: header, then body, then footer.
func (u *tui) vy(w placed) int {
	switch w.region {
	case 0:
		return w.line
	case 1:
		return len(u.head) + w.line
	}
	return len(u.head) + len(u.body) + w.line
}

// ---------------------------------------------------------------------------
// drawing

func (u *tui) render() {
	u.layout()
	var b strings.Builder
	draw := func(y int, r row) {
		fmt.Fprintf(&b, "\x1b[%d;1H\x1b[2K", y)
		x := 1
		for _, c := range r {
			if x > u.W {
				break
			}
			if c.text != "" {
				fmt.Fprintf(&b, "\x1b[%d;%dH%s", y, x, c.text)
			}
			x += c.w
		}
	}
	switch {
	case u.W < tuiMinW || u.H < tuiMinH:
		b.WriteString("\x1b[2J")
		draw(1, row{u.text("", fmt.Sprintf(" tshare needs a window of at least %d×%d (this one is %d×%d)", tuiMinW, tuiMinH, u.W, u.H))})
	case u.mode == "overlay":
		b.WriteString("\x1b[2J")
		for i, l := range u.overlay {
			if i+2 < u.H {
				draw(i+2, row{u.text("", "  "+l)})
			}
		}
		draw(u.H, row{u.text("2", "  any key or click to close")})
	default:
		y := 1
		for _, r := range u.head {
			draw(y, r)
			y++
		}
		bodyH := u.bodyH()
		for i := 0; i < bodyH; i++ {
			if u.scroll+i < len(u.body) {
				draw(y, u.body[u.scroll+i])
			} else {
				draw(y, row{})
			}
			y++
		}
		for _, r := range u.foot {
			draw(y, r)
			y++
		}
	}
	io.WriteString(u.out, b.String())
}

// ---------------------------------------------------------------------------
// input

var mouseRe = regexp.MustCompile(`^\x1b\[<(\d+);(\d+);(\d+)([Mm])$`)

// parseMouse reads an SGR mouse report: button, 1-based column and row, and
// whether it is a press (as opposed to a release).
func parseMouse(k string) (btn, x, y int, press, ok bool) {
	m := mouseRe.FindStringSubmatch(k)
	if m == nil {
		return 0, 0, 0, false, false
	}
	btn, _ = strconv.Atoi(m[1])
	x, _ = strconv.Atoi(m[2])
	y, _ = strconv.Atoi(m[3])
	return btn, x, y, m[4] == "M", true
}

func (u *tui) key(k string) {
	switch { // a paste (or a file dropped on the window) arrives bracketed
	case k == "\x1b[200~":
		u.pasting, u.pasteBuf = true, ""
		return
	case k == "\x1b[201~":
		u.pasting = false
		u.paste(u.pasteBuf)
		return
	case u.pasting:
		u.pasteBuf += k
		return
	}
	btn, x, y, press, isMouse := parseMouse(k)
	switch u.mode {
	case "overlay":
		if !isMouse || press {
			u.mode, u.overlay = "", nil
		}
		return
	case "confirm":
		if isMouse {
			return
		}
		yes := u.yes
		u.mode, u.yes = "", nil
		if k == "y" || k == "Y" {
			yes()
		} else {
			u.status = "cancelled"
		}
		return
	case "edit", "filter":
		if !isMouse {
			u.textKey(k)
		}
		return
	}
	if isMouse {
		switch {
		case btn == 64:
			u.scroll -= 3
		case btn == 65:
			u.scroll += 3
		case press && btn == 0:
			u.click(x, y)
		}
		return
	}
	switch k {
	case "\x1b[A", "k":
		u.move(0, -1)
	case "\x1b[B", "j":
		u.move(0, 1)
	case "\x1b[D", "h", "\x1b[Z":
		u.move(-1, 0)
	case "\x1b[C", "l", "\t":
		u.move(1, 0)
	case "\x1b[5~":
		u.scroll -= u.bodyH() - 1
	case "\x1b[6~":
		u.scroll += u.bodyH() - 1
	case " ":
		u.activate(false)
	case "\r", "\n":
		u.activate(true)
	case "/":
		u.expand = true
		u.editFilter()
	case "e":
		u.focus = "target"
		u.editTarget()
	case "s":
		u.share()
	case "r":
		u.action = "run"
	case "p":
		u.action = "print"
	case "c":
		u.copy(u.commandLine(false), "command")
	case "a":
		if loginAgent != nil {
			u.toggleAgent()
		}
	case "d":
		u.toggleDash()
	case "x":
		for _, o := range u.opts {
			o.on, o.value = o.defOn, ""
		}
		u.status = "every option is back to its default"
	case "?":
		u.help()
	case "q", "\x1b", "\x03", "\x04":
		u.action = "quit"
	}
}

func (u *tui) activate(enter bool) {
	i := u.index(u.focus)
	if i < 0 {
		return
	}
	w := u.widgets[i]
	if enter && w.alt != nil {
		w.alt()
	} else if w.act != nil {
		w.act()
	}
}

// click runs the widget under a screen position, if there is one.
func (u *tui) click(x, y int) {
	region, line := 2, y-1-(u.H-len(u.foot))
	switch bodyTop := len(u.head) + 1; {
	case y <= len(u.head):
		region, line = 0, y-1
	case y < bodyTop+u.bodyH():
		region, line = 1, u.scroll+y-bodyTop
	}
	for _, w := range u.widgets {
		if w.region == region && w.line == line && x >= w.x && x < w.x+w.w {
			u.focus = w.id
			if w.act != nil {
				w.act()
			}
			return
		}
	}
}

// move shifts focus: dx along the reading order, dy to the nearest widget on
// the closest line in that direction. The body scrolls to keep it in view.
func (u *tui) move(dx, dy int) {
	i := u.index(u.focus)
	if i < 0 {
		return
	}
	if j := i + dx; dx != 0 && j >= 0 && j < len(u.widgets) {
		u.focus = u.widgets[j].id
	}
	if dy != 0 {
		cur := u.widgets[i]
		cy, cx := u.vy(cur), cur.x+cur.w/2
		best, bestLines, bestCols := -1, 0, 0
		for j, w := range u.widgets {
			lines := (u.vy(w) - cy) * dy
			if lines <= 0 {
				continue
			}
			cols := w.x + w.w/2 - cx
			if cols < 0 {
				cols = -cols
			}
			if best < 0 || lines < bestLines || lines == bestLines && cols < bestCols {
				best, bestLines, bestCols = j, lines, cols
			}
		}
		if best >= 0 {
			u.focus = u.widgets[best].id
		}
	}
	if j := u.index(u.focus); j >= 0 && u.widgets[j].region == 1 {
		switch line, h := u.widgets[j].line, u.bodyH(); {
		case line < u.scroll+1: // keep the line above (often a heading) in view
			u.scroll = line - 1
		case line >= u.scroll+h:
			u.scroll = line - h + 1
		}
	}
}

func (u *tui) textKey(k string) {
	switch k {
	case "\r", "\n":
		switch {
		case u.mode == "filter":
			u.filter = u.editBuf
		case u.editID == "target":
			u.setTarget(expandHome(cleanPath(u.editBuf)))
		default:
			if o := u.find(u.editID); o != nil {
				o.value, o.on = u.editBuf, u.editBuf != ""
			}
		}
		u.mode = ""
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
		if r, _ := utf8.DecodeRuneInString(k); k != "" && unicode.IsPrint(r) && k[0] != 0x1b {
			u.editBuf += k
		}
	}
	if u.mode == "filter" {
		u.filter, u.scroll = u.editBuf, 0
	}
}

// paste takes pasted text: into the field being typed, or — a path dropped on
// the window — as the target.
func (u *tui) paste(text string) {
	text = strings.Join(strings.Fields(strings.NewReplacer("\r", " ", "\n", " ").Replace(text)), " ")
	if u.mode == "edit" || u.mode == "filter" {
		u.editBuf += text
		if u.mode == "filter" {
			u.filter = u.editBuf
		}
		return
	}
	if u.mode == "" && text != "" {
		u.setTarget(expandHome(cleanPath(text)))
		u.focus, u.status = "target", "target set to "+u.target
	}
}

// cleanPath undoes what a terminal does to a path dropped on it: quotes
// around it, or a backslash before each space.
func cleanPath(p string) string {
	p = strings.TrimSpace(p)
	if n := len(p); n >= 2 && (p[0] == '\'' && p[n-1] == '\'' || p[0] == '"' && p[n-1] == '"') {
		return p[1 : n-1]
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+1 < len(p) {
			i++
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// actions

func (u *tui) editTarget() { u.mode, u.editID, u.editBuf = "edit", "target", u.target }

func (u *tui) editFilter() { u.mode, u.editBuf, u.focus = "filter", u.filter, "filter" }

func (u *tui) editOpt(o *option) {
	u.mode, u.editID, u.editBuf = "edit", o.primary, o.value
	if u.editBuf == "" && o.def != "" && o.def != "0" && !o.secret {
		u.editBuf = o.def
	}
}

// toggleOpt is space or a click: a switch flips; a valued option turns off, or
// asks for its value.
func (u *tui) toggleOpt(o *option) {
	switch {
	case o.isBool:
		o.on = !o.on
	case o.on:
		o.on = false
	default:
		u.editOpt(o)
	}
}

// enterOpt is ⏎: a switch flips; a valued option is typed.
func (u *tui) enterOpt(o *option) {
	if o.isBool {
		o.on = !o.on
		return
	}
	u.editOpt(o)
}

func (u *tui) cycleExpiry(o *option) {
	cur := ""
	if o.on {
		cur = o.value
	}
	next := expiryPresets[0]
	for i, p := range expiryPresets {
		if p == cur {
			next = expiryPresets[(i+1)%len(expiryPresets)]
		}
	}
	o.value, o.on = next, next != ""
}

// copy puts text on the clipboard: the system's, or — over SSH, where that
// would be the remote machine's — the terminal's own, via OSC 52.
func (u *tui) copy(text, what string) {
	if !u.osc52 && u.copyFn(text) {
		u.status = "✓ copied the " + what + " · " + text
		return
	}
	fmt.Fprintf(u.out, "\x1b]52;c;%s\x07", base64.StdEncoding.EncodeToString([]byte(text)))
	u.status = "✓ sent the " + what + " to your terminal's clipboard · " + text
}

func (u *tui) open(link string) {
	u.openFn(link)
	u.status = "opened " + link
}

// async runs work off the UI goroutine and its returned closure back on it.
func (u *tui) async(label string, work func() func()) {
	if u.busy != "" {
		u.status = "one thing at a time — still " + u.busy
		return
	}
	u.busy = label
	go func() {
		done := work()
		u.post <- func() { u.busy = ""; done() }
	}()
}

func oneLine(err error) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(err.Error(), "\n", " · ")), " ")
}

func (u *tui) share() {
	if strings.TrimSpace(u.target) == "" && !u.needsNoTarget() {
		u.focus, u.status = "target", "set a target first (press e) — or tick a mode that needs none, like -u or --room"
		return
	}
	argv := u.argv()
	u.async("starting the share…", func() func() {
		rec, err := launchShare(argv)
		return func() {
			if err != nil {
				u.status = "✗ " + oneLine(err)
				if strings.Contains(err.Error(), "foreground") {
					u.status += "  — press r to run it in this terminal instead"
				}
				return
			}
			u.reload()
			u.focus = "s:" + rec.ID + ":0"
			u.copy(rec.URL, "link")
			u.status = "✓ sharing " + dashName(rec) + " — " + strings.TrimPrefix(u.status, "✓ ")
		}
	})
}

func (u *tui) askStop(r stateRec) {
	u.mode, u.prompt = "confirm", "Stop sharing “"+dashName(r)+"”? Its link stops working.   y / n"
	u.yes = func() {
		u.async("stopping "+dashName(r)+"…", func() func() {
			err := stopShare(r.ID)
			return func() {
				u.reload()
				if err != nil {
					u.status = "✗ " + oneLine(err)
				} else {
					u.status = "✓ stopped " + dashName(r)
				}
			}
		})
	}
}

func (u *tui) toggleDash() {
	on := !u.dashOn
	label := "stopping the dashboard…"
	if on {
		label = "starting the dashboard…"
	}
	u.async(label, func() func() {
		err := u.dash.set(on)
		return func() {
			u.reload()
			switch {
			case err != nil:
				u.status = "✗ " + oneLine(err)
			case on:
				u.status = "✓ dashboard at " + u.dashAt.URL + " · password " + u.dashPW + " · 📋 and 🔑 above copy them"
			default:
				u.status = "✓ dashboard stopped"
			}
		}
	})
}

func (u *tui) toggleAgent() {
	on := !loginAgent.Installed()
	u.async("updating the login agent…", func() func() {
		var err error
		if on {
			err = loginAgent.Install()
		} else {
			err = loginAgent.Remove()
		}
		return func() {
			switch {
			case err != nil:
				u.status = "✗ " + oneLine(err)
			case on:
				u.status = "✓ shares started with “survive reboots” now come back after a restart"
			default:
				u.status = "✓ login agent removed — shares no longer come back after a restart"
			}
		}
	})
}

func (u *tui) showQR(r stateRec) {
	out, err := exec.Command("qrencode", "-t", "UTF8", "-m", "1", r.URL).Output()
	if err != nil {
		u.status = "a QR code needs qrencode — brew install qrencode"
		return
	}
	u.overlay = append([]string{dashName(r), r.URL, ""}, strings.Split(strings.TrimRight(string(out), "\n"), "\n")...)
	u.mode = "overlay"
}

func (u *tui) help() {
	u.mode = "overlay"
	u.overlay = []string{
		"tshare — everything at a glance", "",
		"MOUSE    click any box, button or link. Click an emoji in a share's row to copy",
		"         that link: its main one, 🏠 LAN, 💾 download, 🎮 join, 🎯 host.",
		"         Scroll with the wheel. Drop a file on the window to set the target.",
		"         (Hold Option or Shift to select text the usual way.)", "",
		"MOVE     ↑ ↓ ← → or h j k l · tab · PgUp PgDn",
		"DO       space ticks or presses · ⏎ types a value, or presses",
		"SHARE    e  type the target        s  share it in the background",
		"         r  run it in this terminal instead (for --p2p and friends)",
		"         c  copy the command       p  print it and quit",
		"OPTIONS  /  filter the full list   x  reset every option",
		"MORE     a  restore shares after a reboot (login agent)",
		"         d  dashboard on / off     q  quit — your shares keep running",
	}
}

// ---------------------------------------------------------------------------
// the loop

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

// Terminal modes the screen needs, and their exact undo: the alternate
// screen, a hidden cursor, no line wrap (a too-long cell is clipped, never
// spilled onto the next row), mouse clicks in SGR form, and bracketed paste.
const (
	termEnter = "\x1b[?1049h\x1b[?25l\x1b[?7l\x1b[?1000h\x1b[?1006h\x1b[?2004h"
	termLeave = "\x1b[?2004l\x1b[?1006l\x1b[?1000l\x1b[?7h\x1b[?25h\x1b[?1049l"
)

// run owns the terminal until the user quits, and always puts it back.
func (u *tui) run() (action string, err error) {
	saved, err := stty("-g")
	if err != nil {
		return "", fmt.Errorf("can't read terminal settings: %w", err)
	}
	if _, err := stty("raw", "-echo"); err != nil {
		return "", fmt.Errorf("can't switch the terminal to raw mode: %w", err)
	}
	io.WriteString(u.out, termEnter)
	defer func() {
		io.WriteString(u.out, termLeave)
		stty(saved)
	}()

	keys := make(chan string, 16)
	go func() {
		buf := make([]byte, 4096)
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
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()

	u.reload()
	u.render()
	for u.action == "" {
		select {
		case sig := <-sigs:
			if sig != syscall.SIGWINCH {
				u.action = "quit"
			}
		case chunk, ok := <-keys:
			if !ok {
				u.action = "quit"
				break
			}
			for _, k := range splitKeys(chunk) {
				if u.key(k); u.action != "" {
					break
				}
			}
		case done := <-u.post:
			done()
		case <-tick.C:
			u.reload()
		}
		u.render()
	}
	return u.action, nil
}

// splitKeys breaks one read into keys: CSI/SS3 escape sequences (arrows,
// mouse reports, paste brackets) stay whole.
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
			r >= 0xffe0 && r <= 0xffe6 || r >= 0x1f300 && r <= 0x1faff || r == 0x26a1):
			n += 2
		default:
			n++
		}
	}
	return n
}

// fitW makes plain text exactly w columns: cut with an ellipsis, or padded.
func fitW(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if displayWidth(s) > w {
		var b strings.Builder
		cols := 0
		for _, r := range s {
			rw := displayWidth(string(r))
			if cols+rw > w-1 {
				break
			}
			b.WriteRune(r)
			cols += rw
		}
		s = b.String() + "…"
	}
	return s + strings.Repeat(" ", max(0, w-displayWidth(s)))
}

// midTrunc shortens a link in the middle, keeping the host and the end — the
// two parts that tell links apart.
func midTrunc(s string, w int) string {
	rs := []rune(s)
	if len(rs) <= w || w < 8 {
		return s
	}
	head := (w - 1) * 2 / 3
	return string(rs[:head]) + "…" + string(rs[len(rs)-(w-1-head):])
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
