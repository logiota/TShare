//go:build unix

// tshare — secure secret-link file sharing over Tailscale Funnel.
//
// Default: `tshare <path>` serves a file/dir behind an unguessable token URL
// on the public internet via `tailscale funnel`. Lots of optional knobs:
// passwords, expiry, download limits, upload inboxes, zip, QR, tailnet-only,
// background mode, multi-share management (ls/rm), and a local/LAN mode.
//
// Single binary, stdlib only. macOS + Linux.
//
// main.go is only the entry point and command registry: it names no other
// file's code, so it builds on its own. Every feature file is a module that
// registers its subcommands (and the default share engine) from init().
package main

import (
	"fmt"
	"log"
	"os"
)

var (
	commands   = map[string]func(args []string){}
	defaultRun func(args []string) // bare `tshare [flags] <path…>` — the share engine
)

// register binds a subcommand handler to one or more first-argument names.
func register(run func(args []string), names ...string) {
	for _, n := range names {
		if _, dup := commands[n]; dup {
			panic("tshare: command registered twice: " + n)
		}
		commands[n] = run
	}
}

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	if len(args) > 0 {
		if run, ok := commands[args[0]]; ok {
			run(args[1:])
			return
		}
	}
	if defaultRun == nil {
		fmt.Fprintln(os.Stderr, "tshare: built without the share engine — nothing to run")
		os.Exit(1)
	}
	defaultRun(args)
}
