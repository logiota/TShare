package main

import (
	"fmt"
	"testing"
)

func TestDashNamesLive(t *testing.T) {
	for _, r := range loadStates() {
		raw := dashRawName(r)
		name := dashName(r)
		sub := dashSub(r)
		fmt.Printf("id=%s live=%v mode=%s raw=%q name=%q sub=%q\n",
			r.ID, pidAlive(r.PID), r.Mode, raw, name, sub)
		if r.Mode == "file" && (name == "" || name == "file") {
			t.Errorf("file share %s got bad display name %q raw=%q", r.ID, name, raw)
		}
	}
}

func TestDashNameFallbacks(t *testing.T) {
	cases := []struct {
		r    stateRec
		want string
	}{
		{stateRec{Mode: "file", Title: "photo.png"}, "photo"},
		{stateRec{Mode: "file", Title: "Branches-of-Philosophy.png"}, "Branches of Philosophy"},
		{stateRec{Mode: "file", Title: "The Life as a Mom of Four ｜ KMP Ep.47 [tRN_lWF67Wk].m4a"}, "The Life as a Mom of Four · KMP Ep.47"},
		{stateRec{Mode: "file", Target: "/tmp/video.mp4 (12 MB)"}, "video"},
		{stateRec{Mode: "file", URL: "https://h/tok/My%20File.pdf", Token: "tok"}, "My File"},
		{stateRec{Mode: "server", Title: "localhost:3000"}, "localhost:3000"},
		{stateRec{Mode: "server", Target: "reverse proxy → http://127.0.0.1:8080"}, "127.0.0.1:8080"},
		{stateRec{Mode: "server", Target: "myapp → http://127.0.0.1:3000"}, "myapp"},
		{stateRec{Mode: "inbox", Target: "inbox → /Users/jo/drop"}, "Inbox"},
		{stateRec{Mode: "inbox", Title: "blackhole"}, "Blackhole"},
		{stateRec{Mode: "hub", Title: "stuff"}, "Hub"},
	}
	for _, c := range cases {
		if got := dashName(c.r); got != c.want {
			t.Errorf("dashName(%+v)=%q want %q", c.r, got, c.want)
		}
	}
}

func TestPrettyFileTitle(t *testing.T) {
	cases := map[string]string{
		"photo.png": "photo",
		"Branches-of-Philosophy.png": "Branches of Philosophy",
		"my_cool_clip.mp4":           "my cool clip",
		"Hello World.pdf":            "Hello World",
		"Song Title [aqz-KE-bpKQ].mp3": "Song Title",
		"A ｜ B [abcdef12].m4a":        "A · B",
	}
	for in, want := range cases {
		if got := prettyFileTitle(in); got != want {
			t.Errorf("prettyFileTitle(%q)=%q want %q", in, got, want)
		}
	}
}
