//go:build unix

package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/url"
	"os"
	"path"
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
	Name string `json:"name"`
	Icon string `json:"icon"`
	Sub  string `json:"sub"`
}

func dashIcon(mode string) string {
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

// dashTiles builds one tile per active share (skipping this dashboard's own id).
func (s *share) dashTiles() []dashTile {
	var out []dashTile
	for _, r := range loadStates() {
		if r.ID == s.id || !pidAlive(r.PID) {
			continue
		}
		name := r.Mode
		// a file/dir share: use the last URL path segment as the label
		if u, err := url.Parse(r.URL); err == nil {
			if seg := path.Base(strings.TrimRight(u.Path, "/")); seg != "" && seg != "/" && seg != r.Token {
				name = seg
			}
		}
		if name == "" || name == "dashboard" {
			name = r.Mode
		}
		sub := r.Mode
		if !r.Expires.IsZero() {
			sub += " · " + humanDur(time.Until(r.Expires))
		}
		if r.Password {
			sub += " · 🔒"
		}
		out = append(out, dashTile{URL: r.URL, Name: name, Icon: dashIcon(r.Mode), Sub: sub})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
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

// dashboardTmpl: a light iOS-home-screen grid — rounded icon tiles with labels,
// scrolling vertically. No framework; refreshes the grid every few seconds.
var dashboardTmpl = template.Must(template.New("dash").Parse(`<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><meta name="apple-mobile-web-app-capable" content="yes">
<title>shares</title>
<style>` + pageCSS + `
body{max-width:560px;padding:max(22px,env(safe-area-inset-top)) 16px 60px}
h1{font-size:20px;margin:0 0 2px}
.hint{color:var(--mut);font-size:12px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(84px,1fr));gap:20px 12px}
a.app{display:flex;flex-direction:column;align-items:center;text-decoration:none;color:var(--fg);gap:7px}
a.app .ic{width:62px;height:62px;border-radius:16px;background:var(--card);border:1px solid var(--line);
 display:flex;align-items:center;justify-content:center;font-size:30px;box-shadow:var(--shadow);transition:transform .1s}
a.app:active .ic{transform:scale(.92)}
a.app .lb{font-size:12px;font-weight:500;text-align:center;max-width:84px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
a.app .sub{font-size:10px;color:var(--mut);text-align:center}
.empty{color:var(--mut);font-size:14px;text-align:center;padding:40px 0}
</style></head>
<body>
<h1>📲 Your shares</h1>
<div class="hint">tap to open · this page auto-updates · keep it private</div>
<div class="grid" id="grid"></div>
<div class="foot">powered by tshare · password-gated · don't repost this link</div>{{.Abuse}}
<script>
var TILES = {{.Tiles}};
function fmt(t){
 var g=document.getElementById('grid');
 if(!t.length){ g.outerHTML='<div class="empty">no other shares are running.<br>start one: <code>tshare &lt;path&gt;</code></div>'; return; }
 g.innerHTML='';
 t.forEach(function(x){
  var a=document.createElement('a'); a.className='app'; a.href=x.url; a.target='_blank'; a.rel='noopener';
  var ic=document.createElement('div'); ic.className='ic'; ic.textContent=x.icon;
  var lb=document.createElement('div'); lb.className='lb'; lb.textContent=x.name;
  var sub=document.createElement('div'); sub.className='sub'; sub.textContent=x.sub;
  a.appendChild(ic); a.appendChild(lb); a.appendChild(sub); g.appendChild(a);
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
