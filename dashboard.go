//go:build unix

package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// --dashboard: an iOS-home-screen webui tiling every active share. Its own
// password-gated link (random password minted if none given). Live-refreshed
// from the share state files, minus itself.

type dashTile struct {
	URL  string `json:"url"`
	Name string `json:"name"` // short, human display title
	Full string `json:"full"` // raw filename / target for hover
	Icon string `json:"icon"`
	Sub  string `json:"sub"`
}

// dashIcon picks an emoji from mode + optional filename (so media gets 🎬/🖼).
func dashIcon(mode, name string) string {
	if mode == "file" || mode == "multi" {
		switch strings.ToLower(filepath.Ext(name)) {
		case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".heic", ".svg", ".tif", ".tiff", ".ico":
			return "🖼"
		case ".mp4", ".webm", ".mov", ".m4v", ".mkv", ".avi":
			return "🎬"
		case ".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac":
			return "🎵"
		case ".pdf":
			return "📕"
		case ".zip", ".rar", ".7z", ".tgz", ".gz", ".tar":
			return "📦"
		case ".html", ".htm":
			return "🌐"
		}
	}
	switch mode {
	case "file":
		return "📄"
	case "dir", "multi":
		return "📁"
	case "server":
		return "🖥"
	case "site":
		return "🌐"
	case "inbox":
		return "📥"
	case "hub":
		return "📱"
	case "room":
		return "📹"
	case "call":
		return "☎️"
	case "kuma":
		return "📊"
	default:
		return "🔗"
	}
}

// dashRawName is the canonical name (filename, host, path basename) before prettifying.
func dashRawName(r stateRec) string {
	if t := strings.TrimSpace(r.Title); t != "" && t != "dashboard" && t != "shares" {
		return t
	}
	if n := nameFromTarget(r); n != "" {
		return n
	}
	// URL path last segment (file shares append the filename)
	if u, err := url.Parse(r.URL); err == nil {
		if seg := path.Base(strings.TrimRight(u.Path, "/")); seg != "" && seg != "/" && seg != r.Token {
			if d, err := url.PathUnescape(seg); err == nil && d != "" {
				return d
			}
			return seg
		}
	}
	if r.Mode != "" && r.Mode != "dashboard" {
		return r.Mode
	}
	return "share"
}

// dashName is the visible tile title — cleaned up for humans (no ext, no yt ids).
func dashName(r stateRec) string {
	return prettyShareTitle(r.Mode, dashRawName(r))
}

// prettyShareTitle turns raw share names into short readable labels.
//   Branches-of-Philosophy.png  →  Branches of Philosophy
//   Song [abc123XY].m4a         →  Song
//   tshare-inbox                →  Inbox
func prettyShareTitle(mode, raw string) string {
	raw = strings.TrimSpace(raw)
	switch mode {
	case "inbox":
		if raw == "blackhole" {
			return "Blackhole"
		}
		return "Inbox"
	case "hub":
		return "Hub"
	case "call":
		return "Video call"
	case "kuma":
		return "Uptime Kuma"
	case "dashboard":
		return "Shares"
	case "room":
		if raw != "" && raw != "room" && raw != "video room" {
			return raw
		}
		return "Video room"
	case "server":
		if raw != "" {
			return raw
		}
		return "Server"
	case "file", "multi", "dir", "site":
		if raw == "" {
			return mode
		}
		return prettyFileTitle(raw)
	default:
		if raw != "" {
			return prettyFileTitle(raw)
		}
		return mode
	}
}

// prettyFileTitle strips extensions, yt-dlp [id] tails, and slug punctuation.
func prettyFileTitle(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return name
	}
	// Drop extension when it's a normal file suffix (keep dotted version numbers alone).
	if ext := filepath.Ext(name); len(ext) >= 2 && len(ext) <= 5 {
		rest := name[:len(name)-len(ext)]
		if rest != "" && !strings.HasSuffix(rest, ".") {
			name = rest
		}
	}
	// yt-dlp: "Title [videoid]" or "Title [videoid].ext" already stripped of ext
	if i := strings.LastIndex(name, " ["); i > 0 && strings.HasSuffix(name, "]") {
		id := name[i+2 : len(name)-1]
		if ytIDLike(id) {
			name = strings.TrimSpace(name[:i])
		}
	}
	// normalize odd separators from yt-dlp / shell
	repl := []struct{ old, new string }{
		{"｜", " · "},
		{"|", " · "},
		{" – ", " — "},
		{"  ", " "},
	}
	for _, r := range repl {
		name = strings.ReplaceAll(name, r.old, r.new)
	}
	// slug filenames: Branches-of-Philosophy / my_cool_file
	if !strings.ContainsAny(name, " \t") {
		name = strings.ReplaceAll(name, "_", " ")
		name = strings.ReplaceAll(name, "-", " ")
	}
	return strings.Join(strings.Fields(name), " ")
}

func ytIDLike(id string) bool {
	if n := len(id); n < 6 || n > 16 {
		return false
	}
	for _, c := range id {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// nameFromTarget derives a tile label from the state Target string written by describe().
// Used as a fallback for shares started before Title was added to state.
func nameFromTarget(r stateRec) string {
	t := strings.TrimSpace(r.Target)
	if t == "" {
		return ""
	}
	switch r.Mode {
	case "file":
		// "abs/path/name.ext (1.2 MB)" or "name.ext (downloading…)"
		if i := strings.LastIndex(t, " ("); i > 0 {
			t = t[:i]
		}
		if base := path.Base(t); base != "" && base != "." && base != "/" {
			return base
		}
	case "server":
		// "reverse proxy → http://localhost:8000" or "myapp → http://127.0.0.1:N"
		if i := strings.Index(t, "→"); i >= 0 {
			left := strings.TrimSpace(t[:i])
			right := strings.TrimSpace(t[i+len("→"):])
			if left != "" && left != "reverse proxy" {
				return left
			}
			if u, err := url.Parse(right); err == nil && u.Host != "" {
				return u.Host
			}
			if right != "" {
				return right
			}
		}
	case "site":
		// "website /path (index: index.html)"
		t = strings.TrimPrefix(t, "website ")
		if i := strings.Index(t, " ("); i > 0 {
			t = t[:i]
		}
		if base := path.Base(strings.TrimRight(t, "/")); base != "" && base != "." {
			return base
		}
	case "dir", "hub", "inbox":
		// path, optionally with " (uploads allowed)" / " · copyparty"
		if i := strings.Index(t, " ("); i > 0 {
			t = t[:i]
		}
		if i := strings.Index(t, " · "); i > 0 {
			t = t[:i]
		}
		if strings.HasPrefix(t, "inbox → ") {
			t = strings.TrimPrefix(t, "inbox → ")
		}
		if strings.HasPrefix(t, "hub (2-way remote) → ") {
			t = strings.TrimPrefix(t, "hub (2-way remote) → ")
		}
		if base := path.Base(strings.TrimRight(t, "/")); base != "" && base != "." {
			return base
		}
	case "room":
		if i := strings.Index(t, "→"); i >= 0 {
			right := strings.TrimSpace(t[i+len("→"):])
			if u, err := url.Parse(right); err == nil {
				if seg := path.Base(strings.TrimRight(u.Path, "/")); seg != "" && seg != "/" {
					if d, err := url.PathUnescape(seg); err == nil {
						return d
					}
					return seg
				}
			}
		}
	case "multi":
		return t // "N items"
	case "kuma":
		return "Uptime Kuma"
	case "call":
		return "video call"
	}
	return ""
}

// dashSub is the second line under a tile: size / downloading / host detail + time left.
// Never just "file" — the icon already conveys the kind.
func dashSub(r stateRec) string {
	var parts []string
	if bit := dashDetail(r); bit != "" {
		parts = append(parts, bit)
	}
	if !r.Expires.IsZero() {
		left := time.Until(r.Expires)
		if left <= 0 {
			parts = append(parts, "expired")
		} else {
			parts = append(parts, humanDur(left)+" left")
		}
	}
	if r.Password {
		parts = append(parts, "🔒")
	}
	if len(parts) == 0 {
		return r.Mode
	}
	return strings.Join(parts, " · ")
}

// dashDetail pulls a useful secondary fact from Target (size, downloading, upstream).
// Skips redundant mode words when the title already says Inbox/Hub/etc.
func dashDetail(r stateRec) string {
	t := strings.TrimSpace(r.Target)
	switch r.Mode {
	case "file":
		if strings.Contains(t, "(downloading…)") {
			return "downloading…"
		}
		// "…/name.ext (225.2 KB)" → "225.2 KB"
		if i := strings.LastIndex(t, " ("); i > 0 && strings.HasSuffix(t, ")") {
			return strings.TrimSuffix(t[i+2:], ")")
		}
	case "server":
		if i := strings.Index(t, "→"); i >= 0 {
			right := strings.TrimSpace(t[i+len("→"):])
			if u, err := url.Parse(right); err == nil && u.Host != "" {
				if raw := dashRawName(r); raw != u.Host {
					return u.Host
				}
			}
		}
	case "dir", "site":
		// folder basename may already be the title; add kind only if raw was empty-ish
		if raw := dashRawName(r); raw == r.Mode || raw == "" {
			return r.Mode
		}
	case "multi":
		if t != "" {
			return t
		}
	case "hub", "inbox", "room", "call", "kuma":
		// title already names these; no extra mode word
		return ""
	}
	return ""
}

// dashTiles builds one tile per active share (skipping this dashboard's own id).
func (s *share) dashTiles() []dashTile {
	var out []dashTile
	for _, r := range loadStates() {
		if r.ID == s.id || !pidAlive(r.PID) {
			continue
		}
		raw := dashRawName(r)
		name := prettyShareTitle(r.Mode, raw)
		out = append(out, dashTile{
			URL:  r.URL,
			Name: name,
			Full: raw,
			Icon: dashIcon(r.Mode, raw),
			Sub:  dashSub(r),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func (s *share) renderDashboard(w *respRec) {
	if w.status != 0 {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	b, _ := json.Marshal(s.dashTiles())
	if err := dashboardTmpl.Execute(w, map[string]any{"Tiles": template.JS(b), "Abuse": s.abuseHTML()}); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

func (s *share) dashJSON(w *respRec) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(s.dashTiles())
	w.Write(b)
}

// dashCSS is the dashboard-only stylesheet. Deliberately does NOT include
// pageCSS: that file defines .lb as the image lightbox (position:fixed; inset:0;
// display:none), which collided with tile title labels that used class "lb" —
// titles vanished / stuck as a weird full-screen/left overlay, while hover
// (the title= attribute) still looked correct.
const dashCSS = `
:root { --bg:#ffffff; --fg:#1a1a2e; --mut:#777788; --line:#e8e8ef; --acc:#4f63ff; --card:#f6f6fa; --shadow:0 1px 2px rgba(0,0,0,.06); }
@media (prefers-color-scheme: dark) {
 :root { --bg:#101018; --fg:#ececf4; --mut:#9a9aac; --line:#26263a; --acc:#7d8cff; --card:#181826; --shadow:0 1px 2px rgba(0,0,0,.35); }
}
* { box-sizing:border-box; margin:0; }
body { background:var(--bg); color:var(--fg); font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
 max-width:560px; margin:0 auto; padding:max(22px,env(safe-area-inset-top)) 16px 60px; }
h1 { font-size:20px; font-weight:650; margin:0 0 2px; }
.hint { color:var(--mut); font-size:12px; margin-bottom:20px; }
.grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(100px,1fr)); gap:18px 12px; align-items:start; }
a.app { display:flex; flex-direction:column; align-items:center; text-decoration:none; color:var(--fg); gap:6px; min-width:0; }
a.app .ic { width:62px; height:62px; border-radius:16px; background:var(--card); border:1px solid var(--line);
 display:flex; align-items:center; justify-content:center; font-size:30px; box-shadow:var(--shadow); transition:transform .1s; flex-shrink:0; }
a.app:active .ic { transform:scale(.92); }
/* .nm = tile name (NOT .lb — that is the lightbox class in pageCSS) */
a.app .nm { font-size:12px; font-weight:600; text-align:center; width:100%; max-width:108px; line-height:1.25;
 display:-webkit-box; -webkit-box-orient:vertical; -webkit-line-clamp:3; overflow:hidden;
 word-break:break-word; overflow-wrap:anywhere; position:static; }
a.app .meta { font-size:10px; color:var(--mut); text-align:center; width:100%; max-width:108px; line-height:1.25;
 display:-webkit-box; -webkit-box-orient:vertical; -webkit-line-clamp:2; overflow:hidden; word-break:break-word; }
.foot { color:var(--mut); font-size:12px; margin-top:34px; }
.abuse { color:var(--mut); font-size:11px; margin-top:6px; opacity:.75; }
.abuse a { color:inherit; }
.empty { color:var(--mut); font-size:14px; text-align:center; padding:40px 0; }
`

// dashboardTmpl: iOS-home-screen grid of icon tiles. Each tile stacks icon,
// multi-line title (.nm), and meta (.meta). Hover has the raw filename.
var dashboardTmpl = template.Must(template.New("dash").Parse(`<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-title" content="shares">
<title>shares</title>
<style>` + dashCSS + `</style></head>
<body>
<h1>📲 Your shares</h1>
<div class="hint">tap to open · this page auto-updates · keep it private</div>
<div class="grid" id="grid"></div>
<div class="foot">powered by tshare · password-gated · don't repost this link</div>{{.Abuse}}
<script>
var TILES = {{.Tiles}};
function fmt(t){
 var g=document.getElementById('grid');
 if(!g) return;
 if(!t || !t.length){
  var e=document.createElement('div'); e.className='empty';
  e.innerHTML='no other shares are running.<br>start one: <code>tshare &lt;path&gt;</code>';
  g.replaceWith(e); return;
 }
 if(g.className!=='grid'){ var ng=document.createElement('div'); ng.className='grid'; ng.id='grid'; g.replaceWith(ng); g=ng; }
 g.innerHTML='';
 t.forEach(function(x){
  var a=document.createElement('a'); a.className='app'; a.href=x.url; a.target='_blank'; a.rel='noopener';
  var tip=x.full||x.name||'';
  if(x.sub) tip += (tip?' · ':'')+x.sub;
  a.title=tip;
  var ic=document.createElement('div'); ic.className='ic'; ic.textContent=x.icon||'🔗';
  // class "nm" (name) — never "lb" (lightbox overlay in shared pageCSS)
  var nm=document.createElement('div'); nm.className='nm'; nm.textContent=x.name||'share';
  a.appendChild(ic); a.appendChild(nm);
  if(x.sub){ var meta=document.createElement('div'); meta.className='meta'; meta.textContent=x.sub; a.appendChild(meta); }
  g.appendChild(a);
 });
}
fmt(TILES);
setInterval(function(){ fetch('__shares').then(function(r){return r.json();}).then(fmt).catch(function(){}); }, 5000);
</script>
</body></html>`))

// cmdDashboard: `tshare dash` — mints a random password if none is given, then
// serves the shares webui.
func cmdDashboard(args []string) {
	c := defaultConfig()
	applyConfig(c, args)
	if err := parseArgs(args, c); err != nil {
		os.Exit(2)
	}
	c.Dashboard, c.Paths = true, nil
	if err := runShare(c); err != nil {
		log.Fatalf("tshare: %v", err)
	}
}

func (s *share) renderKuma(w *respRec) {
	if w.status != 0 {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]any{"URL": s.kumaURL, "Abuse": s.abuseHTML()}
	if err := kumaTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}
