//go:build unix

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// tshare agent: a macOS LaunchAgent that runs tshare at login (default: `tshare
// resume`), shaped like what a Homebrew `service` block generates so it can be
// managed by `brew services` later.

const agentLabel = "com.tshare.agent"

func agentPlistPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "LaunchAgents", agentLabel+".plist")
}

func cmdAgent(args []string) {
	if runtime.GOOS != "darwin" {
		fmt.Println("tshare agent is macOS (launchd) only.")
		fmt.Println("On Linux use a systemd --user unit, e.g.:")
		fmt.Println("  systemd-run --user --unit tshare --collect $(command -v tshare) resume")
		return
	}
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "install", "setup", "":
		agentInstall(args[1:])
	case "uninstall", "rm", "remove":
		agentUninstall()
	case "status":
		agentStatus()
	default:
		fmt.Println("usage: tshare agent install [-- <tshare args>]   (default: run `tshare resume` at login)")
		fmt.Println("       tshare agent uninstall")
		fmt.Println("       tshare agent status")
	}
}

func agentInstall(args []string) {
	print, noLoad, keepAlive, keepSet := false, false, false, false
	var runArgs []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--print":
			print = true
		case "--no-load":
			noLoad = true
		case "--keepalive":
			keepAlive, keepSet = true, true
		case "--":
			runArgs = append(runArgs, args[i+1:]...)
			i = len(args)
		default:
			runArgs = append(runArgs, args[i])
		}
	}
	if len(runArgs) == 0 {
		runArgs = []string{"resume"} // restart --persist'd shares at login
	}
	if !keepSet { // long-running share commands should be restarted; `resume` is one-shot
		keepAlive = runArgs[0] != "resume"
	}
	bin, err := os.Executable()
	if err != nil || bin == "" {
		bin, _ = exec.LookPath("tshare")
	}
	plist := agentPlist(agentLabel, bin, runArgs, keepAlive)
	if print {
		fmt.Print(plist)
		return
	}
	path := agentPlistPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Fatalf("tshare: %v", err)
	}
	if err := os.WriteFile(path, []byte(plist), 0o644); err != nil {
		log.Fatalf("tshare: %v", err)
	}
	if out, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil {
		log.Fatalf("tshare: generated plist failed validation: %s", strings.TrimSpace(string(out)))
	}
	fmt.Printf("  ✓ wrote %s\n", path)
	fmt.Printf("    runs at login:  tshare %s   (KeepAlive=%v)\n", strings.Join(runArgs, " "), keepAlive)
	if noLoad {
		fmt.Printf("    load it yourself:  launchctl bootstrap gui/%d %s\n", os.Getuid(), path)
		return
	}
	uid := strconv.Itoa(os.Getuid())
	exec.Command("launchctl", "bootout", "gui/"+uid+"/"+agentLabel).Run() // ignore if not loaded
	if out, err := exec.Command("launchctl", "bootstrap", "gui/"+uid, path).CombinedOutput(); err != nil {
		// older macOS fallback
		if out2, err2 := exec.Command("launchctl", "load", "-w", path).CombinedOutput(); err2 != nil {
			fmt.Printf("  ⚠ plist written but launchctl load failed:\n    %s\n    %s\n",
				strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
			return
		}
	}
	fmt.Println("  ✓ loaded into launchd — it will run at every login")
	fmt.Println("    later, if installed via brew:  brew services start tshare")
}

func agentUninstall() {
	path := agentPlistPath()
	uid := strconv.Itoa(os.Getuid())
	exec.Command("launchctl", "bootout", "gui/"+uid+"/"+agentLabel).Run()
	exec.Command("launchctl", "unload", "-w", path).Run() // belt & braces
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Fatalf("tshare: %v", err)
	}
	fmt.Printf("  ✓ unloaded and removed %s\n", path)
}

func agentStatus() {
	path := agentPlistPath()
	if !fileExists(path) {
		fmt.Println("no tshare agent installed (tshare agent install)")
		return
	}
	fmt.Printf("  plist:  %s\n", path)
	uid := strconv.Itoa(os.Getuid())
	out, err := exec.Command("launchctl", "print", "gui/"+uid+"/"+agentLabel).CombinedOutput()
	if err != nil {
		fmt.Println("  state:  written but not loaded (tshare agent install to load)")
		return
	}
	state := "loaded"
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "state =") {
			state = strings.TrimSpace(line)
			break
		}
	}
	fmt.Printf("  state:  %s\n", state)
}

func agentPlist(label, bin string, argv []string, keepAlive bool) string {
	home, _ := os.UserHomeDir()
	logPath := filepath.Join(home, ".tshare", "logs", "agent.log")
	os.MkdirAll(filepath.Dir(logPath), 0o755)
	// login shells get a fuller PATH than launchd's default, so tailscale/node/
	// tmux resolve — include the common Homebrew + system locations.
	pathEnv := "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
	var pa strings.Builder
	pa.WriteString("\t\t<string>" + xmlEsc(bin) + "</string>\n")
	for _, a := range argv {
		pa.WriteString("\t\t<string>" + xmlEsc(a) + "</string>\n")
	}
	ka := "<false/>"
	if keepAlive {
		ka = "<true/>"
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
%s	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	%s
	<key>WorkingDirectory</key>
	<string>%s</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>%s</string>
	</dict>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
`, xmlEsc(label), pa.String(), ka, xmlEsc(home), xmlEsc(pathEnv), xmlEsc(logPath), xmlEsc(logPath))
}

func xmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func cmdRoom(args []string) {
	c := defaultConfig()
	applyConfig(c, args)
	sub := ""
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "install", "setup":
		parseArgs(args[1:], c) // honor --mirotalk-dir / --mirotalk-port
		if err := mirotalkApp.install(c); err != nil {
			log.Fatalf("tshare: %v", err)
		}
	case "status":
		parseArgs(args[1:], c)
		mirotalkApp.status(c)
	default:
		fmt.Println("usage: tshare room install | status   (start a room with: tshare --room)")
	}
}
func appendConfigKeys(kv map[string]string) error {
	path := configPath()
	if path == "" {
		return errors.New("no config path")
	}
	existing, _ := os.ReadFile(path)
	var add []string
	for k, v := range kv {
		re := regexp.MustCompile(`(?m)^(\s*(?:--)?` + regexp.QuoteMeta(k) + `\s*=\s*).*$`)
		if re.Match(existing) { // key already present → rewrite its value in place
			existing = re.ReplaceAll(existing, []byte("${1}"+v))
			continue
		}
		add = append(add, fmt.Sprintf("%s = %s", k, v))
	}
	if len(add) == 0 {
		return os.WriteFile(path, existing, 0o600) // may have updated values above
	}
	sort.Strings(add)
	block := "# recorded by tshare\n" + strings.Join(add, "\n") + "\n"
	var out string
	switch {
	case len(existing) == 0:
		out = "# tshare config (see config.example)\n[default]\n" + block
	default:
		lines := strings.SplitAfter(string(existing), "\n")
		at := -1 // insert index: after [default], else before the first section
		for i, l := range lines {
			t := strings.TrimSpace(l)
			if t == "[default]" {
				at = i + 1
				break
			}
			if strings.HasPrefix(t, "[") && at == -1 {
				at = i
				break
			}
		}
		if at == -1 { // no sections at all → append (still global)
			at = len(lines)
		}
		out = strings.Join(lines[:at], "") + block + strings.Join(lines[at:], "")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(out), 0o600)
}
