//go:build unix

package main

import (
	"reflect"
	"testing"
)

func TestSplitRunArgsTrailingFlags(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		wantFlags []string
		wantCmd   []string
	}{
		{
			name:      "flags trailing after --",
			args:      []string{"--", "node", "server.js", "--name", "SyqRFBny8dRndtV5", "--persist", "-b", "--tmux"},
			wantFlags: []string{"--name", "SyqRFBny8dRndtV5", "--persist", "-b", "--tmux"},
			wantCmd:   []string{"node", "server.js"},
		},
		{
			name:      "flags before --",
			args:      []string{"--name", "demo", "--tmux", "--", "npm", "start"},
			wantFlags: []string{"--name", "demo", "--tmux"},
			wantCmd:   []string{"npm", "start"},
		},
		{
			name:      "trailing name alone is too ambiguous to lift",
			args:      []string{"--port", "3000", "node", "app.js", "--name", "demo"},
			wantFlags: []string{"--port", "3000"},
			wantCmd:   []string{"node", "app.js", "--name", "demo"},
		},
		{
			name:      "mixed before and trailing",
			args:      []string{"--name", "demo", "--", "node", "app.js", "-b"},
			wantFlags: []string{"--name", "demo", "-b"},
			wantCmd:   []string{"node", "app.js"},
		},
		{
			name:      "plain command untouched",
			args:      []string{"--", "python3", "-m", "http.server", "8000"},
			wantFlags: []string{},
			wantCmd:   []string{"python3", "-m", "http.server", "8000"},
		},
		{
			name:      "app's own trailing value flag left alone",
			args:      []string{"--", "node", "server.js", "-p", "3000"},
			wantFlags: []string{},
			wantCmd:   []string{"node", "server.js", "-p", "3000"},
		},
		{
			name:      "value of lifted flag survives",
			args:      []string{"--", "node", "server.js", "--name", "demo", "--tmux"},
			wantFlags: []string{"--name", "demo", "--tmux"},
			wantCmd:   []string{"node", "server.js"},
		},
		{
			name:      "app flags before a tshare trailing flag",
			args:      []string{"--", "node", "server.js", "--verbose", "-b"},
			wantFlags: []string{"-b"},
			wantCmd:   []string{"node", "server.js", "--verbose"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			flags, cmd := splitRunArgs(c.args)
			if !reflect.DeepEqual(flags, c.wantFlags) {
				t.Errorf("flags = %v, want %v", flags, c.wantFlags)
			}
			if !reflect.DeepEqual(cmd, c.wantCmd) {
				t.Errorf("cmd = %v, want %v", cmd, c.wantCmd)
			}
		})
	}
}
