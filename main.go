//go:build unix

// tshare — secure secret-link file sharing over Tailscale Funnel.
//
// Default: `tshare <path>` serves a file/dir behind an unguessable token URL
// on the public internet via `tailscale funnel`. Lots of optional knobs:
// passwords, expiry, download limits, upload inboxes, zip, QR, tailnet-only,
// background mode, multi-share management (ls/rm), and a local/LAN mode.
//
// Single binary, stdlib only. macOS + Linux.
package main

import (
	"fmt"
	"log"
	"os"
)

// ---------------------------------------------------------------------------
// entry

func main() {
	log.SetFlags(0)
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "ls", "list":
			cmdLs(args[1:])
			return
		case "rm", "stop", "revoke":
			cmdRm(args[1:])
			return
		case "set":
			cmdSet(args[1:])
			return
		case "extend", "-x":
			cmdExtend(args[1:])
			return
		case "panic", "--panic":
			cmdPanic()
			return
		case "room":
			cmdRoom(args[1:])
			return
		case "kuma", "uptime-kuma":
			cmdKuma(args[1:])
			return
		case "dash", "dashboard":
			cmdDashboard(args[1:])
			return
		case "run":
			cmdRun(args[1:])
			return
		case "host":
			cmdHost(args[1:])
			return
		case "agent", "service":
			cmdAgent(args[1:])
			return
		case "tmux":
			cmdTmux(args[1:])
			return
		case "template", "templates":
			cmdTemplate(args[1:])
			return
		case "info":
			cmdInfo(args[1:])
			return
		case "doctor":
			cmdDoctor()
			return
		case "decrypt":
			cmdDecrypt(args[1:])
			return
		case "resume":
			cmdResume(args[1:])
			return
		case "version", "--version", "-v":
			fmt.Println("tshare v" + version)
			return
		case "help", "--help", "-h":
			fmt.Print(usageText)
			return
		}
	}

	c := defaultConfig()
	// config file (#71): defaults < config file/profile < CLI flags
	applyConfig(c, args)
	if err := parseArgs(args, c); err != nil {
		os.Exit(2)
	}
	if c.Once {
		c.MaxDL = 1
	}
	if c.Live {
		c.Progress = true // live implies progressive serving
	}
	if c.H265 { // --265: hardware HEVC to a temp file at constant quality
		c.Transcode, c.Hevc = true, true
		if c.CQ <= 0 || c.CQ > 63 {
			c.CQ = 50
		}
	}
	if err := runShare(c); err != nil {
		log.Fatalf("tshare: %v", err)
	}
}
