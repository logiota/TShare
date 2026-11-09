//go:build unix

package main

// Programmatic share control for front ends (`tshare gui`, the MCP server).
//
// A front end never hosts a share in its own process: it runs this same binary
// as a detached `tshare -b` share and reads back the state that share
// publishes. So a share outlives the browser tab or AI session that started
// it, gets exactly the lifecycle of one started by hand (state file, `tshare
// rm`, --persist, the login agent), and a front end crashing takes nothing down.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// launchFlags go on every front-end launch: detach, report as JSON, and leave
// out the terminal-only niceties (QR, clipboard, auto-opened pages).
var launchFlags = []string{"-b", "--json", "--no-qr", "--no-copy", "--no-open"}

// reservedFlags are the ones front ends set themselves; a caller passing them
// would break the launch (--quiet turns the JSON report into a bare URL).
var reservedFlags = map[string]bool{
	"b": true, "bg": true, "json": true, "quiet": true, "webwiz": true,
}

// launchShare starts a share in the background and returns its published state.
func launchShare(argv []string) (stateRec, error) {
	exe, err := os.Executable()
	if err != nil {
		return stateRec{}, err
	}
	// -b waits up to 60s for a slow start (a launched server, a big download)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, insertArgs(argv, launchFlags...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()

	var rec stateRec
	if i := bytes.IndexByte(out.Bytes(), '{'); i >= 0 {
		json.NewDecoder(bytes.NewReader(out.Bytes()[i:])).Decode(&rec)
	}
	if runErr == nil && rec.ID != "" {
		return rec, nil
	}
	return stateRec{}, launchError(errb.String(), out.String(), runErr)
}

// launchError keeps what a person needs to read: tshare's own message.
func launchError(stderr, stdout string, err error) error {
	for _, text := range []string{stderr, stdout} {
		var lines []string
		for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, strings.TrimPrefix(l, "tshare: "))
			}
		}
		if len(lines) > 0 {
			if len(lines) > 8 { // the tail is where the reason is
				lines = lines[len(lines)-8:]
			}
			return errors.New(strings.Join(lines, "\n"))
		}
	}
	if err != nil {
		return err
	}
	return errors.New("the share didn't report back (check: tshare ls)")
}

// expandHome turns "~/x" into the home directory path, as a shell would.
func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// liveShares lists the shares that are actually running.
func liveShares() []stateRec {
	out := []stateRec{}
	for _, r := range loadStates() {
		if recAlive(r) {
			out = append(out, r)
		}
	}
	return out
}

func isPersisted(id string) bool { return fileExists(persistFile(id)) }

var shareIDRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$`)

// requireLive insists on the EXACT id of a running share. `tshare rm` also
// accepts prefixes and "all"/"--all", which a person types on purpose but a
// remote caller must never trigger by accident — one stray "a" would stop
// every share whose id starts with it.
func requireLive(id string) (stateRec, error) {
	if !shareIDRe.MatchString(id) {
		return stateRec{}, fmt.Errorf("%q is not a share id (see the list of shares)", id)
	}
	for _, r := range liveShares() {
		if r.ID == id {
			return r, nil
		}
	}
	return stateRec{}, fmt.Errorf("no running share has the id %q", id)
}

// stopShare stops one running share exactly as `tshare rm` does.
func stopShare(id string) error {
	if _, err := requireLive(id); err != nil {
		return err
	}
	_, err := runSelf(30*time.Second, "rm", id)
	return err
}

// updateShare changes a running share's options exactly as `tshare set` does.
func updateShare(id string, args []string) (string, error) {
	if _, err := requireLive(id); err != nil {
		return "", err
	}
	return runSelf(15*time.Second, append([]string{"set", id}, args...)...)
}

// shareInfo returns a running share's live stats as JSON.
func shareInfo(id string) (string, error) {
	if _, err := requireLive(id); err != nil {
		return "", err
	}
	return runSelf(15*time.Second, "info", id)
}

func runSelf(timeout time.Duration, args ...string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text == "" {
			return "", err
		}
		return "", errors.New(strings.TrimPrefix(text, "tshare: "))
	}
	return text, nil
}

// checkCallerArgs vets raw flags from outside (an MCP agent's extra_args): only
// tshare's own flags, never the private --__ markers, never the launch flags a
// front end owns, and every value-taking flag must have its value.
func checkCallerArgs(args []string) error {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			return fmt.Errorf("%q isn't a flag — give the file or folder as the path", a)
		}
		if !isTshareFlag(a) || tshareInternalFlag(a) {
			return fmt.Errorf("%s isn't a tshare option (see the options list)", a)
		}
		if reservedFlags[flagName(a)] {
			return fmt.Errorf("%s is set by the caller automatically", a)
		}
		if runValueFlag(a) && !strings.Contains(a, "=") {
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a value", a)
			}
			i++
		}
	}
	return nil
}
