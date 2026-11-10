//go:build unix && !nogui

package main

// `tshare gui`: point-and-click tshare in your browser. Pick a file or folder
// (native picker), tick options — survive reboots, password, website, root,
// the full catalogue — press Share; see every running share with copy, open,
// QR and stop; flip the dashboard and the reboot-restore agent on and off.
//
// Stdlib only: a loopback HTTP server on a random port, behind a random secret
// path, serving one page embedded below. Shares are launched as detached
// `tshare -b` processes (lifecycle.go), so closing the GUI takes nothing down.
// Optional — build with -tags nogui to leave it out.
//
// A local server that can publish your files is a target for every website
// you visit, so: it binds 127.0.0.1 only; checks the Host header (no DNS
// rebinding); needs the secret path for everything; and accepts a change only
// as a JSON POST carrying a custom header from its own origin — which a
// cross-site form or fetch can't send without a CORS preflight it never grants.

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

func init() { register(cmdGUI, "gui") }

func cmdGUI(args []string) {
	fs := flag.NewFlagSet("gui", flag.ExitOnError)
	port := fs.Int("port", 0, "port to listen on (default: random)")
	noOpen := fs.Bool("no-open", false, "print the address instead of opening a browser")
	fs.Parse(args)

	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(*port))
	if err != nil {
		log.Fatalf("tshare gui: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	g := &guiServer{
		secret: randToken(24),
		hosts:  map[string]bool{fmt.Sprintf("127.0.0.1:%d", p): true, fmt.Sprintf("localhost:%d", p): true},
		dashPW: map[string]string{},
	}
	g.origins = map[string]bool{}
	for h := range g.hosts {
		g.origins["http://"+h] = true
	}
	link := fmt.Sprintf("http://127.0.0.1:%d/%s/", p, g.secret)
	fmt.Printf("\n  tshare gui  %s\n", link)
	fmt.Println("  Ctrl-C to quit — shares you start keep running (manage them later: tshare ls / rm)")
	if !*noOpen {
		openBrowser(link)
	}
	srv := &http.Server{Handler: g, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n  gui closed")
}

type guiServer struct {
	secret  string
	hosts   map[string]bool
	origins map[string]bool
	mu      sync.Mutex
	dashPW  map[string]string // dashboard share id → the password we minted for it
}

func (g *guiServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if !g.hosts[r.Host] { // DNS rebinding: a hostile name pointed at 127.0.0.1
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	seg, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if subtle.ConstantTimeCompare([]byte(seg), []byte(g.secret)) != 1 {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodPost {
		if r.Header.Get("X-Tshare-GUI") != "1" ||
			!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") ||
			(r.Header.Get("Origin") != "" && !g.origins[r.Header.Get("Origin")]) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	} else if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	switch rest {
	case "":
		if !strings.HasSuffix(r.URL.Path, "/") {
			http.Redirect(w, r, "/"+g.secret+"/", http.StatusFound)
			return
		}
		nonce := randToken(16)
		h.Set("Content-Security-Policy", "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; "+
			"script-src 'nonce-"+nonce+"'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(strings.Replace(guiPage, "{{NONCE}}", nonce, 1)))
	case "api/catalog":
		g.json(w, guiCatalog())
	case "api/state":
		g.json(w, g.state())
	case "api/compose":
		var req guiCompose
		if !g.decode(w, r, &req) {
			return
		}
		b, err := req.build()
		if err != nil {
			g.json(w, map[string]any{"error": err.Error()})
			return
		}
		g.json(w, map[string]any{"preview": b.commandLine(true), "isDir": b.isDirTarget(),
			"stack": b.stack, "host": b.host, "needsNoTarget": b.needsNoTarget()})
	case "api/start":
		var req guiCompose
		if !g.decode(w, r, &req) {
			return
		}
		b, err := req.build()
		if err == nil && strings.TrimSpace(b.target) == "" && !b.needsNoTarget() {
			err = fmt.Errorf("choose a file, folder or URL to share first")
		}
		if err != nil {
			g.json(w, map[string]any{"error": err.Error()})
			return
		}
		rec, err := launchShare(b.argv())
		if err != nil {
			g.json(w, map[string]any{"error": err.Error()})
			return
		}
		g.json(w, map[string]any{"share": guiShareView(rec)})
	case "api/stop":
		var req struct{ ID string }
		if !g.decode(w, r, &req) {
			return
		}
		g.result(w, stopShare(req.ID))
	case "api/pick":
		var req struct{ Kind string }
		if !g.decode(w, r, &req) {
			return
		}
		path, err := pickPath(req.Kind == "folder")
		if err != nil {
			g.json(w, map[string]any{"error": err.Error()})
			return
		}
		g.json(w, map[string]any{"path": path})
	case "api/agent":
		var req struct{ On bool }
		if !g.decode(w, r, &req) {
			return
		}
		switch {
		case loginAgent == nil:
			g.json(w, map[string]any{"error": "this build has no login agent"})
		case req.On:
			g.result(w, loginAgent.Install())
		default:
			g.result(w, loginAgent.Remove())
		}
	case "api/dash":
		var req struct{ On bool }
		if !g.decode(w, r, &req) {
			return
		}
		g.result(w, g.setDashboard(req.On))
	case "api/qr":
		guiQR(w, r.URL.Query().Get("url"))
	default:
		http.NotFound(w, r)
	}
}

func (g *guiServer) json(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func (g *guiServer) result(w http.ResponseWriter, err error) {
	if err != nil {
		g.json(w, map[string]any{"error": err.Error()})
		return
	}
	g.json(w, map[string]any{"ok": true})
}

func (g *guiServer) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}

// guiCompose is a share described as data: the target, website mode, and the
// options ticked (by name → true/false or a value).
type guiCompose struct {
	Target string
	Host   *bool
	Opts   map[string]any
}

func (q guiCompose) build() (*builder, error) {
	b := newBuilder(nil)
	b.setTarget(expandHome(strings.TrimSpace(q.Target)))
	if q.Host != nil && b.isDirTarget() {
		b.host = *q.Host // an explicit choice beats detection
	}
	names := make([]string, 0, len(q.Opts))
	for n := range q.Opts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := b.set(n, q.Opts[n]); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// guiCatalog is the option catalogue as the page needs it, minus the flags a
// front end sets itself.
func guiCatalog() map[string]any {
	b := newBuilder(nil)
	type opt struct {
		Name, Label, Section, Desc, Hint, Def string
		Bool, Secret, DefOn                   bool
	}
	var opts []opt
	for _, o := range b.opts {
		if reservedFlags[o.primary] {
			continue
		}
		def := o.def
		if o.secret || def == "0" || def == "false" {
			def = ""
		}
		opts = append(opts, opt{Name: o.primary, Label: o.label(), Section: o.section, Desc: o.desc,
			Hint: o.hint, Def: def, Bool: o.isBool, Secret: o.secret, DefOn: o.defOn})
	}
	return map[string]any{"sections": b.sections, "options": opts}
}

type guiShare struct {
	ID, Title, URL, Mode, Expires string
	Password, Persisted           bool
	Downloads, Uploads            int64
}

func guiShareView(r stateRec) guiShare {
	v := guiShare{ID: r.ID, Title: dashName(r), URL: r.URL, Mode: r.Mode, Password: r.Password,
		Persisted: isPersisted(r.ID), Downloads: r.Downloads, Uploads: r.Uploads}
	if r.GameJoin != "" {
		v.URL = r.GameJoin
	}
	if !r.Expires.IsZero() {
		v.Expires = humanDur(time.Until(r.Expires))
	}
	return v
}

func (g *guiServer) state() map[string]any {
	shares := []guiShare{}
	var dash map[string]any
	for _, r := range liveShares() {
		if r.Mode == "dashboard" {
			g.mu.Lock()
			pw := g.dashPW[r.ID]
			g.mu.Unlock()
			dash = map[string]any{"id": r.ID, "url": r.URL, "password": pw}
			continue
		}
		shares = append(shares, guiShareView(r))
	}
	_, qrErr := exec.LookPath("qrencode")
	return map[string]any{
		"shares": shares, "dashboard": dash,
		"agent": loginAgent != nil && loginAgent.Installed(), "agentSupported": loginAgent != nil && runtime.GOOS == "darwin",
		"pickers": pickerAvailable(), "qr": qrErr == nil,
	}
}

// setDashboard starts or stops the dashboard share. The GUI mints its password
// itself, so it can show it — the share's own auto-minted one never leaves the
// detached child.
func (g *guiServer) setDashboard(on bool) error {
	for _, r := range liveShares() {
		if r.Mode == "dashboard" {
			if on {
				return nil
			}
			return stopShare(r.ID)
		}
	}
	if !on {
		return nil
	}
	pw := randToken(4)
	rec, err := launchShare([]string{"dash", "-p", pw})
	if err != nil {
		return err
	}
	g.mu.Lock()
	g.dashPW[rec.ID] = pw
	g.mu.Unlock()
	return nil
}

// pickPath opens the OS's own file or folder chooser and returns the choice.
func pickPath(folder bool) (string, error) {
	var cmd *exec.Cmd
	switch {
	case runtime.GOOS == "darwin":
		what := "choose file with prompt \"Share which file?\""
		if folder {
			what = "choose folder with prompt \"Share which folder?\""
		}
		// "activate" brings osascript's own dialog to the front — no Apple
		// Events to another app, so no automation permission prompt.
		cmd = exec.Command("osascript", "-e", "activate", "-e", "POSIX path of ("+what+")")
	case haveExec("zenity"):
		cmd = exec.Command("zenity", "--file-selection", "--title=Share with tshare")
		if folder {
			cmd.Args = append(cmd.Args, "--directory")
		}
	case haveExec("kdialog"):
		if folder {
			cmd = exec.Command("kdialog", "--getexistingdirectory", ".")
		} else {
			cmd = exec.Command("kdialog", "--getopenfilename", ".")
		}
	default:
		return "", fmt.Errorf("no file picker here — type the path instead")
	}
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("cancelled")
	}
	p := strings.TrimSpace(string(out))
	if folder && len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p, nil
}

func pickerAvailable() bool {
	return runtime.GOOS == "darwin" || haveExec("zenity") || haveExec("kdialog")
}

// guiQR renders a share link as an SVG QR code via qrencode, when installed.
func guiQR(w http.ResponseWriter, link string) {
	u, err := url.Parse(link)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || len(link) > 2048 {
		http.Error(w, "bad url", http.StatusBadRequest)
		return
	}
	out, err := exec.Command("qrencode", "-t", "SVG", "-m", "1", "-o", "-", link).Output()
	if err != nil {
		http.Error(w, "qrencode not installed", http.StatusNotImplemented)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Write(out)
}

// guiPage is the whole front end: one page, no external assets, no backticks
// (it lives in a Go raw string), talking to the JSON API above.
const guiPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>tshare</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#14161a;--mut:#667085;--line:#e4e7ec;--acc:#4f46e5;--acc2:#eef2ff;--ok:#12b76a;--bad:#d92d20;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#0d0f14;--card:#161a22;--fg:#e8eaf0;--mut:#8b93a7;--line:#262c38;--acc:#818cf8;--acc2:#1e2140}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
header{display:flex;align-items:center;gap:18px;flex-wrap:wrap;padding:16px 24px;border-bottom:1px solid var(--line);background:var(--card);position:sticky;top:0;z-index:5}
header h1{font-size:17px;margin:0;font-weight:700;letter-spacing:-.01em}header h1 span{color:var(--acc)}
.toggles{display:flex;gap:16px;flex-wrap:wrap;margin-left:auto}
main{max-width:980px;margin:0 auto;padding:22px 18px 80px;display:grid;gap:18px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
.card h2{font-size:15px;margin:0 0 12px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
input[type=text],input[type=password],select{font:inherit;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:9px;padding:8px 10px}
input[type=text]:focus,input[type=password]:focus,select:focus{outline:2px solid var(--acc);outline-offset:-1px}
#target{flex:1;min-width:220px}
button{font:inherit;border:1px solid var(--line);background:var(--bg);color:inherit;border-radius:9px;padding:7px 12px;cursor:pointer}
button:hover{border-color:var(--acc)}button.primary{background:var(--acc);border-color:var(--acc);color:#fff;font-weight:600;padding:9px 20px}
button.primary:disabled{opacity:.55;cursor:wait}button.danger:hover{border-color:var(--bad);color:var(--bad)}
.quick{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:8px 18px;margin:14px 0 4px}
label.chk{display:flex;gap:8px;align-items:flex-start;cursor:pointer;padding:3px 0}
label.chk input[type=checkbox]{margin-top:3px;accent-color:var(--acc);width:15px;height:15px;flex:none}
label.chk input[type=text],label.chk input[type=password]{padding:5px 8px;width:150px}
.sw{display:flex;gap:8px;align-items:center;cursor:pointer;font-weight:500}
.sw input{appearance:none;width:34px;height:20px;border-radius:20px;background:var(--line);position:relative;cursor:pointer;transition:.15s;margin:0}
.sw input::after{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:#fff;transition:.15s;box-shadow:0 1px 2px #0003}
.sw input:checked{background:var(--acc)}.sw input:checked::after{left:16px}
.mut{color:var(--mut)}.small{font-size:12.5px}
.detected{margin-top:10px;padding:8px 12px;border-radius:9px;background:var(--acc2)}
details.sec{border-top:1px solid var(--line)}details.sec summary{padding:9px 0;cursor:pointer;font-weight:600;font-size:13px;letter-spacing:.02em}
.opt{display:grid;grid-template-columns:auto 1fr;gap:2px 9px;padding:6px 0 8px}
.opt input[type=checkbox]{margin-top:3px;accent-color:var(--acc)}.opt .name{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.opt .desc{grid-column:2;color:var(--mut);font-size:12.5px}.opt input[type=text],.opt input[type=password]{grid-column:2;padding:5px 8px;max-width:340px}
#filter{width:100%;margin:6px 0 4px}
pre{margin:0;white-space:pre-wrap;word-break:break-all;font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--bg);border:1px solid var(--line);border-radius:9px;padding:10px 12px}
.bar{display:flex;gap:10px;align-items:center;margin-top:14px;flex-wrap:wrap}
.msg{padding:9px 12px;border-radius:9px;margin-top:12px;white-space:pre-wrap}.msg.err{background:#d92d201a;color:var(--bad)}.msg.ok{background:#12b76a1a}
.share{display:grid;grid-template-columns:1fr auto;gap:4px 12px;padding:12px 0;border-top:1px solid var(--line)}.share:first-child{border-top:0}
.share .t{font-weight:600}.share a{color:var(--acc);word-break:break-all}.share .acts{display:flex;gap:6px;align-items:start;flex-wrap:wrap;justify-content:flex-end}
.badge{display:inline-block;font-size:11.5px;padding:1px 7px;border-radius:20px;background:var(--acc2);margin-right:4px}
.qr{grid-column:1/-1}.qr img{width:170px;height:170px;background:#fff;padding:8px;border-radius:9px}
.empty{color:var(--mut);padding:6px 0}
</style></head><body>
<header><h1>t<span>share</span></h1>
 <div class="toggles">
  <label class="sw" id="agentWrap" title="A macOS login agent that runs 'tshare resume' at login, so --persist shares come back after a reboot"><input type="checkbox" id="agent"> Restore shares after reboot</label>
  <label class="sw" title="An iOS-home-screen web page tiling all your shares, on its own password-gated link"><input type="checkbox" id="dash"> Dashboard</label>
 </div>
</header>
<main>
 <div class="card" id="dashCard" hidden></div>
 <section class="card">
  <h2>Share something</h2>
  <div class="row">
   <input type="text" id="target" placeholder="a file, a folder, or a URL — or pick one" autocomplete="off" spellcheck="false">
   <button id="pickFile" hidden>File…</button><button id="pickFolder" hidden>Folder…</button>
  </div>
  <div class="detected" id="detected" hidden></div>
  <div class="quick" id="quick"></div>
  <details class="sec" id="all"><summary>All options <span class="mut small" id="count"></span></summary>
   <input type="text" id="filter" placeholder="filter options…" autocomplete="off">
   <div id="sections"></div>
  </details>
  <div class="bar"><button class="primary" id="go">Share</button><span class="mut small">runs in the background — closing this page doesn't stop it</span></div>
  <pre id="preview" style="margin-top:12px">$ tshare</pre>
  <div id="msg"></div>
 </section>
 <section class="card"><h2>Running shares</h2><div id="shares" class="empty">…</div></section>
</main>
<script nonce="{{NONCE}}">
"use strict";
const H={"X-Tshare-GUI":"1","Content-Type":"application/json"};
async function api(path,body){
  const r=await fetch("api/"+path,body===undefined?{}:{method:"POST",headers:H,body:JSON.stringify(body)});
  let j={};try{j=await r.json()}catch(e){j={error:"HTTP "+r.status}}
  if(!r.ok&&!j.error)j.error="HTTP "+r.status;return j}
const $=id=>document.getElementById(id);
function el(tag,attrs,...kids){const e=document.createElement(tag);for(const k in attrs||{}){if(k==="class")e.className=attrs[k];else if(k.startsWith("on"))e.addEventListener(k.slice(2),attrs[k]);else if(attrs[k]!==false&&attrs[k]!=null)e.setAttribute(k,attrs[k]===true?"":attrs[k])}for(const k of kids)if(k!=null)e.append(k);return e}

let cat={options:[],sections:[]},byName={},sel={},host=null,timer=null;
// the few options most people want, front and centre
const QUICK=[["persist","Survive reboots — same link after a restart"],["password","Password"],["expires","Expires"],
 ["root","Publish at the root (https://host/) — /absolute paths work"],["tailnet","Tailnet only — not public"],
 ["local","Local network only — no Tailscale"],["allow-upload","Visitors can upload too"],["once","One download, then gone"]];
const EXPIRES=[["","default (15 days; sites never)"],["1h","1 hour"],["1d","1 day"],["1w","1 week"],["30d","30 days"],["never","never"]];

function valueOf(o){return sel[o.Name]!==undefined?sel[o.Name]:(o.Bool?o.DefOn:"")}
function setOpt(name,v){const o=byName[name];if(!o)return;
  if(o.Bool&&v===o.DefOn)delete sel[name];else if(!o.Bool&&v==="")delete sel[name];else sel[name]=v;
  syncControls(name);compose()}
function syncControls(name){const o=byName[name],v=valueOf(o);
  document.querySelectorAll('[data-opt="'+name+'"]').forEach(c=>{
    if(c.type==="checkbox")c.checked=o.Bool?!!v:v!=="";
    else if(document.activeElement!==c)c.value=v||"";
    if(c.dataset.role==="val")c.hidden=!o.Bool&&v===""&&!c.dataset.open})}

function quickControl(name,label){const o=byName[name];if(!o)return null;
  if(name==="expires"){const s=el("select",{"data-opt":name,onchange:e=>setOpt(name,e.target.value)});
    EXPIRES.forEach(([v,t])=>s.append(el("option",{value:v},t)));return el("label",{class:"chk",title:o.Desc},el("span",{},label+" "),s)}
  if(!o.Bool){const inp=el("input",{type:o.Secret?"password":"text","data-opt":name,placeholder:o.Hint||"value",
      autocomplete:"off",oninput:e=>setOpt(name,e.target.value)});return el("label",{class:"chk",title:o.Desc},el("span",{},label+" "),inp)}
  return el("label",{class:"chk",title:o.Desc},el("input",{type:"checkbox","data-opt":name,onchange:e=>setOpt(name,e.target.checked)}),el("span",{},label))}

function optionRow(o){
  if(o.Bool)return el("label",{class:"opt"},el("input",{type:"checkbox","data-opt":o.Name,onchange:e=>setOpt(o.Name,e.target.checked)}),
    el("span",{class:"name"},o.Label),el("span",{class:"desc"},o.Desc+(o.DefOn?" (on by default)":"")));
  const val=el("input",{type:o.Secret?"password":"text","data-opt":o.Name,"data-role":"val",placeholder:o.Hint||o.Def||"value",autocomplete:"off",hidden:true,
    oninput:e=>{e.target.dataset.open="1";setOpt(o.Name,e.target.value)}});
  const box=el("input",{type:"checkbox","data-opt":o.Name,onchange:e=>{if(e.target.checked){val.hidden=false;val.dataset.open="1";val.value=val.value||o.Def||"";val.focus();if(val.value)setOpt(o.Name,val.value)}else{delete val.dataset.open;setOpt(o.Name,"")}}});
  return el("div",{class:"opt"},box,el("span",{class:"name"},o.Label+(o.Hint?" "+o.Hint:"")),
    el("span",{class:"desc"},o.Desc+(o.Def&&!o.Secret?" (default: "+o.Def+")":"")),val)}

function renderCatalog(){
  const q=$("quick");QUICK.forEach(([n,l])=>{const c=quickControl(n,l);if(c)q.append(c)});
  const box=$("sections");
  cat.sections.forEach(s=>{const d=el("details",{class:"sec","data-sec":s},el("summary",{},s.charAt(0)+s.slice(1).toLowerCase()));
    cat.options.filter(o=>o.Section===s).forEach(o=>d.append(optionRow(o)));box.append(d)});
  cat.options.forEach(o=>syncControls(o.Name))}

$("filter").addEventListener("input",e=>{const f=e.target.value.toLowerCase();
  document.querySelectorAll("#sections details.sec").forEach(d=>{let any=false;
    d.querySelectorAll(".opt").forEach(r=>{const hit=!f||r.textContent.toLowerCase().includes(f);r.hidden=!hit;any=any||hit});
    d.hidden=!any;if(f)d.open=any})})

function body(){return{Target:$("target").value,Host:host,Opts:sel}}
function compose(){clearTimeout(timer);timer=setTimeout(async()=>{
  const r=await api("compose",body());
  if(r.error){$("preview").textContent="⚠ "+r.error;return}
  $("preview").textContent="$ "+r.preview;
  const n=Object.keys(sel).length;$("count").textContent=n?"· "+n+" changed":"";
  const d=$("detected");
  if(r.isDir&&r.stack){d.hidden=false;d.replaceChildren(el("label",{class:"chk"},
    el("input",{type:"checkbox",checked:r.host,onchange:e=>{host=e.target.checked;compose()}}),
    el("span",{},"Website / app mode — detected ",el("b",{},r.stack),". tshare serves it as a site, or runs it as an app (",el("code",{},"tshare host"),"). Untick to share it as files.")))}
  else d.hidden=true},150)}
$("target").addEventListener("input",()=>{host=null;compose()});

function say(text,ok){$("msg").replaceChildren(text?el("div",{class:"msg "+(ok?"ok":"err")},text):"")}
$("go").addEventListener("click",async()=>{const b=$("go");b.disabled=true;b.textContent="Starting…";say("");
  const r=await api("start",body());b.disabled=false;b.textContent="Share";
  if(r.error){say(r.error,false);return}
  const s=r.share;say(el("span",{},"✓ Sharing ",el("b",{},s.Title)," at ",el("a",{href:s.URL,target:"_blank",rel:"noreferrer"},s.URL)),true);
  navigator.clipboard&&navigator.clipboard.writeText(s.URL).catch(()=>{});refresh()});

async function pick(kind){const r=await api("pick",{Kind:kind});if(r.path){$("target").value=r.path;host=null;compose()}else if(r.error&&r.error!=="cancelled")say(r.error,false)}
$("pickFile").addEventListener("click",()=>pick("file"));$("pickFolder").addEventListener("click",()=>pick("folder"));

let qrOn={},state={};
function shareRow(s,canQR){
  const meta=[s.Mode,s.Expires?"expires in "+s.Expires:"never expires",s.Downloads?s.Downloads+" downloads":null,s.Uploads?s.Uploads+" uploads":null].filter(Boolean).join(" · ");
  const acts=el("div",{class:"acts"},
    el("button",{onclick:()=>navigator.clipboard.writeText(s.URL)},"Copy"),
    el("button",{onclick:()=>window.open(s.URL,"_blank","noreferrer")},"Open"),
    canQR?el("button",{onclick:()=>{qrOn[s.ID]=!qrOn[s.ID];render()}},"QR"):null,
    el("button",{class:"danger",onclick:async()=>{if(!confirm("Stop sharing “"+s.Title+"”? The link stops working."))return;const r=await api("stop",{ID:s.ID});if(r.error)alert(r.error);refresh()}},"Stop"));
  const row=el("div",{class:"share"},el("div",{},
    el("div",{class:"t"},s.Title," ",s.Persisted?el("span",{class:"badge",title:"comes back after a reboot"},"↻ persists"):null,s.Password?el("span",{class:"badge"},"🔒 password"):null),
    el("a",{href:s.URL,target:"_blank",rel:"noreferrer"},s.URL),el("div",{class:"mut small"},meta)),acts);
  if(qrOn[s.ID])row.append(el("div",{class:"qr"},el("img",{alt:"QR code",src:"api/qr?url="+encodeURIComponent(s.URL)})));
  return row}

function render(){const st=state;
  const box=$("shares");box.className="";
  if(!st.shares||!st.shares.length){box.className="empty";box.textContent="Nothing shared right now.";}
  else box.replaceChildren(...st.shares.map(s=>shareRow(s,st.qr)));
  $("agent").checked=!!st.agent;$("agentWrap").hidden=!st.agentSupported;
  $("dash").checked=!!st.dashboard;
  const dc=$("dashCard");
  if(st.dashboard){dc.hidden=false;dc.replaceChildren(el("h2",{},"Dashboard"),
    el("div",{},el("a",{href:st.dashboard.url,target:"_blank",rel:"noreferrer"},st.dashboard.url)),
    el("div",{class:"mut small"},st.dashboard.password?"password: "+st.dashboard.password+" (any username)":"password set when it was started — toggle it off and on for a new one"))}
  else dc.hidden=true;
  $("pickFile").hidden=$("pickFolder").hidden=!st.pickers}
async function refresh(){state=await api("state");render()}

$("agent").addEventListener("change",async e=>{const r=await api("agent",{On:e.target.checked});if(r.error)alert(r.error);refresh()});
$("dash").addEventListener("change",async e=>{e.target.disabled=true;const r=await api("dash",{On:e.target.checked});e.target.disabled=false;if(r.error)alert(r.error);refresh()});

(async()=>{cat=await api("catalog");cat.options.forEach(o=>byName[o.Name]=o);renderCatalog();compose();refresh();setInterval(refresh,3000)})();
</script></body></html>`
