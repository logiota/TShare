//go:build unix

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func init() { register(cmdAgent, "agent", "service") }

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
	if print {
		fmt.Print(agentPlist(agentLabel, agentBin(), runArgs, keepAlive))
		return
	}
	path, err := writeAgent(runArgs, keepAlive)
	if err != nil {
		log.Fatalf("tshare: %v", err)
	}
	fmt.Printf("  ✓ wrote %s\n", path)
	fmt.Printf("    runs at login:  tshare %s   (KeepAlive=%v)\n", strings.Join(runArgs, " "), keepAlive)
	if noLoad {
		fmt.Printf("    load it yourself:  launchctl bootstrap gui/%d %s\n", os.Getuid(), path)
		return
	}
	if err := loadAgent(path); err != nil {
		fmt.Printf("  ⚠ plist written but launchctl load failed:\n    %v\n", err)
		return
	}
	fmt.Println("  ✓ loaded into launchd — it will run at every login")
	fmt.Println("    later, if installed via brew:  brew services start tshare")
}

// agentBin is the tshare binary the agent should run.
func agentBin() string {
	bin, err := os.Executable()
	if err != nil || bin == "" {
		bin, _ = exec.LookPath("tshare")
	}
	return bin
}

// writeAgent renders and validates the plist, returning its path.
func writeAgent(runArgs []string, keepAlive bool) (string, error) {
	path := agentPlistPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(agentPlist(agentLabel, agentBin(), runArgs, keepAlive)), 0o644); err != nil {
		return "", err
	}
	if out, err := exec.Command("plutil", "-lint", path).CombinedOutput(); err != nil {
		return "", fmt.Errorf("generated plist failed validation: %s", strings.TrimSpace(string(out)))
	}
	return path, nil
}

// loadAgent (re)loads the plist into launchd, falling back to older syntax.
func loadAgent(path string) error {
	uid := strconv.Itoa(os.Getuid())
	exec.Command("launchctl", "bootout", "gui/"+uid+"/"+agentLabel).Run() // ignore if not loaded
	out, err := exec.Command("launchctl", "bootstrap", "gui/"+uid, path).CombinedOutput()
	if err == nil {
		return nil
	}
	out2, err2 := exec.Command("launchctl", "load", "-w", path).CombinedOutput()
	if err2 == nil {
		return nil
	}
	return fmt.Errorf("%s / %s", strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
}

// agentInstalled reports whether the login agent's plist is in place.
func agentInstalled() bool { return fileExists(agentPlistPath()) }

// ensurePersistAgent is what makes --persist mean what it says. A resume record
// alone restores nothing: something has to run `tshare resume` after a reboot.
// Requiring the user to know that was the whole failure mode — a share flagged
// --persist that quietly never came back — so the first --persist share installs
// the login agent itself, says so, and says how to undo it.
func ensurePersistAgent(c *config) {
	if c.Quiet || agentInstalled() {
		return
	}
	if runtime.GOOS != "darwin" {
		log.Printf("  ⚠ --persist records this share, but nothing restores it automatically here.")
		log.Printf("    run `tshare resume` at login (systemd --user service, .profile, …)")
		return
	}
	path, err := writeAgent([]string{"resume"}, false)
	if err == nil {
		err = loadAgent(path)
	}
	if err != nil {
		log.Printf("  ⚠ --persist needs a login agent to restore shares, and installing it failed:")
		log.Printf("    %v", err)
		log.Printf("    install it yourself:  tshare agent install")
		return
	}
	log.Printf("  ✓ --persist: installed the login agent, so these shares come back after a reboot")
	log.Printf("    (runs `tshare resume` at login · undo: tshare agent uninstall)")
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
	if !agentInstalled() {
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
