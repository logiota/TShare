//go:build unix

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// subcommands

func loadStates() []stateRec {
	out := []stateRec{} // non-nil so ls --json prints [] not null
	des, err := os.ReadDir(stateDir())
	if err != nil {
		return out
	}
	for _, de := range des {
		if !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(stateDir(), de.Name()))
		if err != nil {
			continue
		}
		var rec stateRec
		if json.Unmarshal(b, &rec) != nil {
			continue
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

func cmdLs(args []string) {
	recs := loadStates()
	for _, a := range args {
		if a == "--json" || a == "-json" {
			b, _ := json.MarshalIndent(recs, "", "  ")
			fmt.Println(string(b))
			return
		}
	}
	if len(recs) == 0 {
		fmt.Println("no shares. start one: tshare <path>")
		return
	}
	fmt.Printf("\n  %-8s %-6s %-6s %-5s %-9s %s\n", "ID", "MODE", "STATE", "DL", "EXPIRES", "URL")
	defer fmt.Println("\n  stop: tshare rm <id> · change: tshare set <id> -p pw -e 3d -n 9 · stats: tshare info <id>")
	for _, r := range recs {
		state := "live"
		if !pidAlive(r.PID) {
			state = "dead"
		}
		exp := "never"
		if !r.Expires.IsZero() {
			if time.Now().After(r.Expires) {
				exp = "expired"
			} else {
				exp = humanDur(time.Until(r.Expires))
			}
		}
		dl := strconv.FormatInt(r.Downloads, 10)
		if r.MaxDL > 0 {
			dl += "/" + strconv.FormatInt(r.MaxDL, 10)
		}
		fmt.Printf("  %-8s %-6s %-6s %-5s %-9s %s\n", r.ID, r.Mode, state, dl, exp, r.URL)
		fmt.Printf("  %-8s → %s\n", "", r.Target)
	}
}

func cmdRm(args []string) {
	all := false
	var ids []string
	for _, a := range args {
		if a == "--all" || a == "-a" || a == "all" {
			all = true
		} else {
			ids = append(ids, a)
		}
	}
	recs := loadStates()
	if len(recs) == 0 {
		fmt.Println("nothing to stop")
		return
	}
	match := func(r stateRec) bool {
		if all {
			return true
		}
		for _, id := range ids {
			if r.ID == id || strings.HasPrefix(r.ID, id) {
				return true
			}
		}
		return false
	}
	n := 0
	for _, r := range recs {
		if !match(r) {
			continue
		}
		n++
		if pidAlive(r.PID) {
			syscall.Kill(r.PID, syscall.SIGTERM)
			for i := 0; i < 30 && pidAlive(r.PID); i++ {
				time.Sleep(100 * time.Millisecond)
			}
			if pidAlive(r.PID) {
				syscall.Kill(r.PID, syscall.SIGKILL)
			}
		}
		// belt & braces: remove funnel mount + state even if process is gone;
		// reap owned managed servers (run/host/room) if the share died uncleanly.
		if !pidAlive(r.PID) {
			reapProcs(r.Procs, syscall.SIGTERM)
		}
		if !r.Local {
			c := &config{Tailnet: r.Tailnet, HTTPSPort: r.HTTPSPort}
			tsUnmount(c, r.Token)
			if r.RootMount && !pidAlive(r.PID) {
				tsUnmount(c, "")
			}
		}
		os.Remove(stateFile(r.ID))
		fmt.Printf("  ✓ stopped %s (%s)\n", r.ID, r.URL)
	}
	if n == 0 {
		fmt.Println("no matching share id — see: tshare ls")
	}
}

// reapProcs stops managed servers recorded in a share's state: kill each
// process group with sig, or kill the tmux window (which ends its process too).
func reapProcs(procs []procRec, sig syscall.Signal) {
	for _, p := range procs {
		if p.Tmux != "" {
			exec.Command("tmux", "kill-window", "-t", p.Tmux).Run()
		} else if p.Pid > 0 && pidAlive(p.Pid) {
			syscall.Kill(-p.Pid, sig)
		}
	}
}

// cmdPanic is the big red button: kill every share NOW (SIGKILL, no graceful
// drain), tear down every funnel mount, and wipe all local state — share
// records, resume/persist records and control sockets — so no token survives.
func cmdPanic() {
	recs := loadStates()
	for _, r := range recs {
		if pidAlive(r.PID) {
			syscall.Kill(r.PID, syscall.SIGKILL) // no waiting — this is a panic
		}
		// SIGKILL means the share's own cleanup never ran: reap owned managed
		// servers (process groups / tmux windows) and the funnel ROOT mount too.
		reapProcs(r.Procs, syscall.SIGKILL)
		if !r.Local {
			tsUnmount(&config{Tailnet: r.Tailnet, HTTPSPort: r.HTTPSPort}, r.Token)
			if r.RootMount {
				tsUnmount(&config{Tailnet: r.Tailnet, HTTPSPort: r.HTTPSPort}, "")
			}
		}
		os.Remove(stateFile(r.ID))
		os.Remove(persistFile(r.ID))
		os.Remove(filepath.Join(ctlDir(), r.ID+".sock"))
	}
	// belt & braces: clear any orphaned records/sockets left by crashed shares.
	wipeDir := func(dir string) {
		if des, err := os.ReadDir(dir); err == nil {
			for _, de := range des {
				os.Remove(filepath.Join(dir, de.Name()))
			}
		}
	}
	wipeDir(stateDir())
	wipeDir(persistDir())
	wipeDir(ctlDir())
	fmt.Printf("  ✓ panic: killed %d share(s), unmounted funnels, wiped all tokens & state\n", len(recs))
}

// cmdExtend pushes out a running share's expiry. With no duration it DOUBLES
// the time remaining (the default); pass a duration to add that instead.
// A share with no expiry ("never") is already immortal, so it's a no-op.
func cmdExtend(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: tshare extend <id> [duration]   (no duration = double the time left)")
		return
	}
	id := resolveID(args[0])
	form := url.Values{}
	if len(args) >= 2 && strings.TrimSpace(args[1]) != "" {
		form.Set("extend", args[1]) // add this much
	} else {
		form.Set("extend", "double") // default: double remaining
	}
	client, err := ctlClient(id)
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	resp, err := client.Post("http://tshare/set", "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("tshare: %s", strings.TrimSpace(string(b)))
	}
	var out struct {
		Changed []string `json:"changed"`
	}
	if json.Unmarshal(b, &out) == nil && len(out.Changed) > 0 {
		for _, ch := range out.Changed {
			fmt.Printf("  ✓ %s\n", ch)
		}
	} else {
		fmt.Println(strings.TrimSpace(string(b)))
	}
}

func cmdDoctor() {
	okm := func(ok bool) string {
		if ok {
			return "✓"
		}
		return "✗"
	}
	c := &config{HTTPSPort: 443}
	fmt.Println("\n  tshare doctor")

	bin, err := tsBin(c)
	fmt.Printf("  %s tailscale CLI: %s\n", okm(err == nil), orErr(bin, err))
	if err != nil {
		fmt.Println("    → install from https://tailscale.com/download")
		return
	}
	if out, err := exec.Command(bin, "version").Output(); err == nil {
		fmt.Printf("  ✓ version: %s\n", strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0]))
	}

	info, err := tsStatus(c)
	fmt.Printf("  %s backend running: %s\n", okm(err == nil), orErr("yes", err))
	if info != nil {
		dns := strings.TrimSuffix(info.Self.DNSName, ".")
		fmt.Printf("  %s MagicDNS name: %s\n", okm(dns != ""), orErr(dns, nil))
		fmt.Printf("  %s HTTPS certs: %v\n", okm(len(info.CertDomains) > 0), info.CertDomains)
		if dns == "" {
			fmt.Println("    → enable MagicDNS + HTTPS: https://tailscale.com/kb/1153/enabling-https")
		}
	}

	out, ferr := exec.Command(bin, "funnel", "status").CombinedOutput()
	fmt.Printf("  %s funnel available: ", okm(ferr == nil))
	if ferr == nil {
		fmt.Println("yes")
	} else {
		fmt.Printf("no\n    %s\n    → enable the funnel attribute: https://tailscale.com/kb/1223/funnel\n",
			strings.TrimSpace(string(out)))
	}

	// A funnel link is only truly public if the *.ts.net name resolves on the
	// PUBLIC internet. Funnel can report "on" (cert + attribute present) while
	// Tailscale hasn't published the DNS record — then links work on the tailnet
	// but 404/NXDOMAIN for everyone else. Check it against a public resolver.
	if info != nil {
		if dns := strings.TrimSuffix(info.Self.DNSName, "."); dns != "" {
			pub := resolvesPublicly(dns)
			fmt.Printf("  %s funnel DNS resolves publicly: %v\n", okm(pub), pub)
			if !pub {
				fmt.Printf("    ⚠ %s has no public DNS record — Funnel links work on your tailnet\n", dns)
				fmt.Println("      but NOT the public internet. Re-publish it, then re-create shares:")
				fmt.Println("        tailscale funnel reset && tailscale up")
				fmt.Println("      and confirm HTTPS + Funnel are enabled: https://tailscale.com/kb/1223/funnel")
			}
		}
	}

	yb, yerr := ytBin()
	fmt.Printf("  %s yt-dlp (optional): %s\n", okm(yerr == nil), orErr(yb, yerr))
	if yerr != nil {
		fmt.Println("    → for URL sharing: brew install yt-dlp (or pipx install yt-dlp)")
	}
	if _, err := exec.LookPath("qrencode"); err != nil {
		fmt.Println("  ✗ qrencode (optional): not found → brew install qrencode for QR codes")
	} else {
		fmt.Println("  ✓ qrencode (optional): yes")
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		fmt.Println("  ✗ ffmpeg (optional): not found → brew install ffmpeg for --transcode/--hevc")
	} else {
		fmt.Println("  ✓ ffmpeg (optional): yes")
	}
	if inv := copypartyInvocation(&config{}); inv != nil {
		fmt.Printf("  ✓ copyparty (optional): %s\n", strings.Join(inv, " "))
	} else {
		fmt.Println("  ✗ copyparty (optional): not found → pip install copyparty for richer folders")
	}

	fmt.Println("\n  all good? share something: tshare <path>  ·  tshare <video-url>")
}

func orErr(ok string, err error) string {
	if err != nil {
		return err.Error()
	}
	return ok
}

// ---------------------------------------------------------------------------
// control socket: change options on a running share (tshare set / info)

func ctlDir() string {
	d := filepath.Join(filepath.Dir(stateDir()), "ctl")
	os.MkdirAll(d, 0o700)
	return d
}

func (s *share) ctlServe() {
	s.ctlPath = filepath.Join(ctlDir(), s.id+".sock")
	os.Remove(s.ctlPath)
	ln, err := net.Listen("unix", s.ctlPath)
	if err != nil {
		if !s.cfg.Quiet {
			log.Printf("warn: control socket unavailable: %v", err)
		}
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		s.stateMu.Lock()
		rec := s.stateRec(s.lastPort)
		s.stateMu.Unlock()
		resp := struct {
			stateRec
			Uptime      string `json:"uptime"`
			ViewersNow  int64  `json:"viewers_now"`
			BytesServed int64  `json:"bytes_served"`
		}{rec, time.Since(s.createdAt).Round(time.Second).String(), s.viewers.Load(), s.bytesServed.Load()}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.MarshalIndent(resp, "", "  ")
		w.Write(b)
	})
	mux.HandleFunc("/set", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var changed []string
		if r.Form.Has("password") {
			s.mu.Lock()
			s.password = r.Form.Get("password")
			s.mu.Unlock()
			if r.Form.Get("password") == "" {
				changed = append(changed, "password cleared")
			} else {
				changed = append(changed, "password updated")
			}
		}
		if r.Form.Has("expires") {
			d, err := parseDuration(r.Form.Get("expires"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			if d == 0 {
				s.expiresAt = time.Time{}
				changed = append(changed, "expiry removed")
			} else {
				s.expiresAt = time.Now().Add(d)
				changed = append(changed, "expires "+s.expiresAt.Format("Jan 2 15:04"))
			}
			s.mu.Unlock()
		}
		if r.Form.Has("extend") {
			note, err := s.doExtend(r.Form.Get("extend"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			changed = append(changed, note)
		}
		if r.Form.Has("max") {
			n, err := strconv.ParseInt(r.Form.Get("max"), 10, 64)
			if err != nil || n < 0 {
				http.Error(w, "max must be a non-negative integer", http.StatusBadRequest)
				return
			}
			s.maxDL.Store(n)
			changed = append(changed, fmt.Sprintf("max downloads → %d", n))
		}
		s.updateState() // after releasing s.mu (lock order: stateMu → mu)
		if !s.cfg.Quiet && len(changed) > 0 {
			log.Printf("⚙ settings changed: %s", strings.Join(changed, "; "))
		}
		w.Header().Set("Content-Type", "application/json")
		b, _ := json.Marshal(map[string]any{"ok": true, "changed": changed})
		w.Write(b)
	})
	go http.Serve(ln, mux)
}

// resolveID expands a (possibly prefix) id to a known share id.
func resolveID(id string) string {
	for _, r := range loadStates() {
		if r.ID == id || strings.HasPrefix(r.ID, id) {
			return r.ID
		}
	}
	return id
}

func ctlClient(id string) (*http.Client, error) {
	sock := filepath.Join(ctlDir(), id+".sock")
	if _, err := os.Stat(sock); err != nil {
		return nil, fmt.Errorf("share %q has no control socket here — is it running? (tshare ls)", id)
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}, nil
}

func cmdSet(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: tshare set <id> [-p password] [-e duration|never] [-n max-downloads]")
		return
	}
	id := resolveID(args[0])
	fs := flag.NewFlagSet("set", flag.ExitOnError)
	pw := fs.String("p", "", "")
	fs.StringVar(pw, "password", "", "")
	exp := fs.String("e", "", "")
	fs.StringVar(exp, "expires", "", "")
	max := fs.String("n", "", "")
	fs.StringVar(max, "max", "", "")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: tshare set <id> [-p password] [-e duration|never] [-n max-downloads]")
	}
	fs.Parse(args[1:])
	form := url.Values{}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "p", "password":
			form.Set("password", *pw)
		case "e", "expires":
			form.Set("expires", *exp)
		case "n", "max":
			form.Set("max", *max)
		}
	})
	if len(form) == 0 {
		fmt.Println("nothing to change — pass -p, -e and/or -n")
		return
	}
	client, err := ctlClient(id)
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	resp, err := client.Post("http://tshare/set", "application/x-www-form-urlencoded",
		strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("tshare: %s", strings.TrimSpace(string(b)))
	}
	var out struct {
		Changed []string `json:"changed"`
	}
	if json.Unmarshal(b, &out) == nil && len(out.Changed) > 0 {
		for _, ch := range out.Changed {
			fmt.Printf("  ✓ %s\n", ch)
		}
	} else {
		fmt.Println(strings.TrimSpace(string(b)))
	}
}

func cmdInfo(args []string) {
	if len(args) == 0 {
		fmt.Println("usage: tshare info <id>")
		return
	}
	id := resolveID(args[0])
	client, err := ctlClient(id)
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	resp, err := client.Get("http://tshare/info")
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	fmt.Println(strings.TrimSpace(string(b)))
}

// ---------------------------------------------------------------------------
// interactive: change options on a running foreground share by typing them

func (s *share) repl() {
	fmt.Fprintln(os.Stderr, "  ⌨  live controls — type options to change them, e.g.:")
	fmt.Fprintln(os.Stderr, "       -p secret   -e 2d   -n 5   --no-password   info   stop")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch line {
		case "":
			continue
		case "stop", "quit", "exit", "q":
			s.trigger("typed stop")
			return
		case "help", "?":
			fmt.Fprintln(os.Stderr, "  options: -p <pw> | --no-password | -e <dur|never> | -x [dur] | -n <N> | info | stop")
		case "info":
			fmt.Fprintf(os.Stderr, "  ↳ %d downloads · %d uploads · %d viewing · expires %s\n",
				s.dl.Load(), s.upCount.Load(), s.viewers.Load(), s.expiresLabel())
		case "-x", "x", "extend":
			s.replExtend("")
		default:
			if f := strings.Fields(line); len(f) == 2 && (f[0] == "-x" || f[0] == "x" || f[0] == "extend") {
				s.replExtend(f[1])
				continue
			}
			s.applyOptionLine(line)
		}
	}
}

// replExtend handles the live `-x [dur]` control: double the remaining time,
// or add an explicit duration.
func (s *share) replExtend(spec string) {
	note, err := s.doExtend(spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ? %v\n", err)
		return
	}
	s.updateState()
	fmt.Fprintf(os.Stderr, "  ⚙ %s\n", note)
}

// abuseHTML returns the small-font notice for share pages, or "" when neither
// --abuse-contact nor --legal is set. Two opt-in flavours:
//
//	--abuse-contact  →  "Report abuse / request takedown: <contact>"
//	--legal          →  a minimal copyright + DMCA-§512 removal line
//
// Note: US law mandates NO specific banner for a self-hosted personal share;
// --legal is the closest honest "bare minimum" (a visible infringement/removal
// path), not a legal guarantee. Kept deliberately unobtrusive.
func (s *share) abuseHTML() template.HTML {
	contact := strings.TrimSpace(s.cfg.AbuseContact)
	if contact == "" && !s.cfg.Legal {
		return ""
	}
	if s.cfg.Legal {
		who := "the operator of this link"
		if contact != "" {
			who = contactLink(contact)
		}
		return template.HTML(`<div class="abuse">© Shared content remains the property of its ` +
			`respective owners. Report infringement or request removal: ` + who + `</div>`)
	}
	return template.HTML(`<div class="abuse">Report abuse / request takedown: ` + contactLink(contact) + `</div>`)
}

// contactLink renders an abuse/takedown contact as a mailto:/https: link, or
// plain escaped text if it's neither. Shared by the opt-in abuse line and the
// always-on ⚑ report button.
func contactLink(c string) string {
	e := template.HTMLEscapeString(c)
	switch {
	case strings.Contains(c, "@") && !strings.Contains(c, " "):
		return `<a href="mailto:` + e + `">` + e + `</a>`
	case strings.HasPrefix(c, "http://") || strings.HasPrefix(c, "https://"):
		return `<a href="` + e + `" rel="nofollow noreferrer">` + e + `</a>`
	default:
		return e
	}
}

func (s *share) expiresLabel() string {
	t := s.getExpires()
	if t.IsZero() {
		return "never"
	}
	return humanDur(time.Until(t))
}

// applyOptionLine parses a line of flags and applies them to the live share.
func (s *share) applyOptionLine(line string) {
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pw := fs.String("p", "\x00", "")
	fs.StringVar(pw, "password", "\x00", "")
	noPw := fs.Bool("no-password", false, "")
	exp := fs.String("e", "\x00", "")
	fs.StringVar(exp, "expires", "\x00", "")
	maxs := fs.String("n", "\x00", "")
	fs.StringVar(maxs, "max", "\x00", "")
	if err := fs.Parse(shellSplit(line)); err != nil {
		fmt.Fprintf(os.Stderr, "  ? %v (try: help)\n", err)
		return
	}
	var changed []string
	if *noPw {
		s.mu.Lock()
		s.password = ""
		s.mu.Unlock()
		changed = append(changed, "password cleared")
	} else if *pw != "\x00" {
		s.mu.Lock()
		s.password = *pw
		s.mu.Unlock()
		changed = append(changed, "password updated")
	}
	if *exp != "\x00" {
		d, err := parseDuration(*exp)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ? bad duration %q\n", *exp)
			return
		}
		s.mu.Lock()
		if d == 0 {
			s.expiresAt = time.Time{}
		} else {
			s.expiresAt = time.Now().Add(d)
		}
		s.mu.Unlock()
		changed = append(changed, "expiry "+s.expiresLabel())
	}
	if *maxs != "\x00" {
		n, err := strconv.ParseInt(*maxs, 10, 64)
		if err != nil || n < 0 {
			fmt.Fprintln(os.Stderr, "  ? -n needs a non-negative integer")
			return
		}
		s.maxDL.Store(n)
		changed = append(changed, fmt.Sprintf("max-dl → %d", n))
	}
	if len(changed) == 0 {
		fmt.Fprintln(os.Stderr, "  ? nothing changed (try: help)")
		return
	}
	s.updateState()
	fmt.Fprintf(os.Stderr, "  ⚙ %s\n", strings.Join(changed, "; "))
}
