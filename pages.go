//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// HTML pages

const pageCSS = `
:root { --bg:#ffffff; --fg:#1a1a2e; --mut:#777788; --line:#e8e8ef; --acc:#4f63ff; --card:#f6f6fa; }
@media (prefers-color-scheme: dark) {
 :root { --bg:#101018; --fg:#ececf4; --mut:#9a9aac; --line:#26263a; --acc:#7d8cff; --card:#181826; }
}
* { box-sizing:border-box; margin:0; }
body { background:var(--bg); color:var(--fg); font:15px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; max-width:780px; margin:0 auto; padding:28px 18px 60px; }
h1 { font-size:18px; font-weight:650; margin-bottom:4px; }
.crumbs { color:var(--mut); font-size:13px; margin-bottom:18px; }
.crumbs a { color:var(--acc); text-decoration:none; }
table { width:100%; border-collapse:collapse; }
td { padding:9px 8px; border-bottom:1px solid var(--line); }
td.sz, td.tm { color:var(--mut); font-size:13px; white-space:nowrap; text-align:right; }
a.f { color:var(--fg); text-decoration:none; }
a.f:hover { color:var(--acc); }
.dir { font-weight:600; }
td.dl { width:30px; text-align:center; }
td.dl a { color:var(--acc); text-decoration:none; font-size:15px; }
.bar { display:flex; gap:10px; margin:14px 0 20px; flex-wrap:wrap; }
.btn { background:var(--acc); color:#fff; border:none; border-radius:8px; padding:8px 14px; font-size:14px; text-decoration:none; cursor:pointer; }
.btn.sec { background:var(--card); color:var(--fg); border:1px solid var(--line); }
.drop { border:2px dashed var(--line); border-radius:12px; padding:34px; text-align:center; color:var(--mut); margin-top:18px; }
.drop.on { border-color:var(--acc); color:var(--acc); }
.done { color:var(--acc); font-size:13px; margin-top:10px; white-space:pre-line; }
.foot { color:var(--mut); font-size:12px; margin-top:34px; }
.abuse { color:var(--mut); font-size:11px; margin-top:6px; opacity:.75; }
.abuse a { color:inherit; }
.lb { position:fixed; inset:0; background:rgba(0,0,0,.92); display:none; align-items:center; justify-content:center; z-index:50; }
.lb.on { display:flex; }
.lb img { max-width:94vw; max-height:90vh; border-radius:8px; }
.lb .x { position:fixed; top:14px; right:18px; color:#fff; font-size:26px; cursor:pointer; }
.lb .nav { position:fixed; top:50%; transform:translateY(-50%); color:#fff; font-size:40px; cursor:pointer; padding:0 18px; user-select:none; opacity:.7; }
.lb .prev { left:4px; } .lb .next { right:4px; }
`

const uploadJS = `
function wire(box, input, status){
 function send(files){
  if(!files.length) return;
  var fd = new FormData();
  for (var i=0;i<files.length;i++) fd.append('f', files[i]);
  var xhr = new XMLHttpRequest();
  xhr.open('POST', document.body.dataset.upload || '__upload');
  xhr.upload.onprogress = function(e){
   if (e.lengthComputable) status.textContent = 'uploading… ' + Math.round(100*e.loaded/e.total) + '%';
  };
  xhr.onload = function(){
   if (xhr.status === 200) {
    var r = JSON.parse(xhr.responseText);
    status.textContent = 'received: ' + r.saved.join(', ');
    if (document.body.dataset.reload === '1') setTimeout(function(){ location.reload(); }, 700);
   } else status.textContent = 'failed: ' + xhr.responseText;
  };
  xhr.onerror = function(){ status.textContent = 'network error'; };
  status.textContent = 'uploading… 0%';
  xhr.send(fd);
 }
 box.addEventListener('dragover', function(e){ e.preventDefault(); box.classList.add('on'); });
 box.addEventListener('dragleave', function(){ box.classList.remove('on'); });
 box.addEventListener('drop', function(e){ e.preventDefault(); box.classList.remove('on'); send(e.dataTransfer.files); });
 box.addEventListener('click', function(){ input.click(); });
 input.addEventListener('change', function(){ send(input.files); });
}
wire(document.getElementById('drop'), document.getElementById('file'), document.getElementById('status'));
`

// galleryJS turns image rows into a swipeable lightbox (#31).
const galleryJS = `
(function(){
 var imgs = [].slice.call(document.querySelectorAll('a.img'));
 if(!imgs.length) return;
 var lb=document.getElementById('lb'), el=document.getElementById('lbimg'), idx=0;
 function show(i){ idx=(i+imgs.length)%imgs.length; el.src=imgs[idx].getAttribute('data-full'); lb.classList.add('on'); }
 function hide(){ lb.classList.remove('on'); el.src=''; }
 imgs.forEach(function(a,i){ a.addEventListener('click', function(e){ e.preventDefault(); show(i); }); });
 lb.querySelector('.x').addEventListener('click', hide);
 lb.querySelector('.prev').addEventListener('click', function(e){ e.stopPropagation(); show(idx-1); });
 lb.querySelector('.next').addEventListener('click', function(e){ e.stopPropagation(); show(idx+1); });
 lb.addEventListener('click', function(e){ if(e.target===lb) hide(); });
 document.addEventListener('keydown', function(e){ if(!lb.classList.contains('on'))return;
  if(e.key==='Escape')hide(); else if(e.key==='ArrowRight')show(idx+1); else if(e.key==='ArrowLeft')show(idx-1); });
})();
`

var dirTmpl = template.Must(template.New("dir").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>{{.Title}}</title>
<style>` + pageCSS + `</style></head>
<body data-reload="1" data-upload="{{.UploadURL}}">
<h1>📁 {{.Title}}</h1>
<div class="crumbs">{{range .Crumbs}}<a href="{{.Href}}">{{.Name}}</a> / {{end}}</div>
<div class="bar">
 <a class="btn" href="{{.ZipHref}}">⬇ download all (.zip)</a>
 {{if .AllowUp}}<button class="btn sec" onclick="document.getElementById('file').click()">⇡ upload here</button>{{end}}
</div>
<table>
{{range .Entries}}<tr>
 <td><a class="f {{if .IsDir}}dir{{end}}{{if .Img}} img{{end}}" href="{{.Href}}"{{if .Img}} data-full="{{.Href}}?raw=1"{{end}}>{{.Icon}} {{.Name}}</a></td>
 <td class="dl">{{if .DlHref}}<a href="{{.DlHref}}" title="download">⬇</a>{{end}}</td>
 <td class="sz">{{.Size}}</td><td class="tm">{{.Mod}}</td>
</tr>{{end}}
{{if not .Entries}}<tr><td colspan="4" style="color:var(--mut)">empty folder</td></tr>{{end}}
</table>
{{if .AllowUp}}
<div class="drop" id="drop">drop files here or click to upload</div>
<input type="file" id="file" multiple style="display:none">
<div class="done" id="status"></div>
<script>` + uploadJS + `</script>
{{end}}
{{if .Gallery}}
<div class="lb" id="lb"><span class="x">✕</span><span class="nav prev">‹</span><img id="lbimg" src=""><span class="nav next">›</span></div>
<script>` + galleryJS + `</script>
{{end}}
<div class="foot">shared with tshare · link is private — don't repost it</div>{{.Abuse}}
</body></html>`))

var inboxTmpl = template.Must(template.New("inbox").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>send files</title>
<style>` + pageCSS + `</style></head>
<body data-upload="{{.UploadURL}}">
<h1>⇡ Send files</h1>
<div class="crumbs">files go straight to the owner of this link</div>
<div class="drop" id="drop">drop files here or click to choose</div>
<input type="file" id="file" multiple style="display:none">
<div class="done" id="status"></div>
<noscript><form method="post" action="{{.UploadURL}}" enctype="multipart/form-data" style="margin-top:16px">
<input type="file" name="f" multiple> <button class="btn" type="submit">upload</button></form></noscript>
<script>` + uploadJS + `</script>
<div class="foot">powered by tshare · link is private — don't repost it</div>{{.Abuse}}
</body></html>`))

// roomTmpl is the --room landing page: a token-gated door to a MiroTalk video
// room. The Join button links straight to the room URL; an optional display
// name is appended as ?name=.
var roomTmpl = template.Must(template.New("room").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>join video room</title>
<style>` + pageCSS + `
.room { text-align:center; padding:22px 0; }
.room .big { font-size:46px; margin-bottom:2px; }
.room .rn { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; background:var(--card); border:1px solid var(--line); border-radius:8px; padding:4px 10px; display:inline-block; margin:8px 0 18px; }
.room input.dn { width:min(320px,90%); padding:9px 12px; border:1px solid var(--line); border-radius:8px; background:var(--card); color:var(--fg); font-size:15px; margin-bottom:14px; display:block; margin-left:auto; margin-right:auto; }
.room a.go { font-size:16px; padding:12px 26px; display:inline-block; }
</style></head>
<body>
<div class="room">
 <div class="big">📹</div>
 <h1>Video room</h1>
 <div class="rn">{{.RoomName}}</div>
 <input class="dn" id="dn" placeholder="Your name (optional)" autocomplete="name">
 <a class="btn go" id="join" href="{{.RoomURL}}" target="_blank" rel="noopener noreferrer">Join call →</a>
 <div class="foot">powered by tshare · opens MiroTalk in a new tab · link is private — don't repost it</div>{{.Abuse}}
</div>
<script>
(function(){
 var join=document.getElementById('join'), dn=document.getElementById('dn'), base=join.getAttribute('href');
 function upd(){ var n=dn.value.trim(); join.href = n ? base+(base.indexOf('?')<0?'?':'&')+'name='+encodeURIComponent(n) : base; }
 dn.addEventListener('input', upd);
 dn.addEventListener('keydown', function(e){ if(e.key==='Enter'){ upd(); join.click(); } });
})();
</script>
</body></html>`))

// kumaTmpl is the token-gated landing for --kuma: a door to the Uptime Kuma
// dashboard (served at the funnel root). Uptime Kuma has its own login.
var kumaTmpl = template.Must(template.New("kuma").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Uptime Kuma</title>
<style>` + pageCSS + `
.room { text-align:center; padding:22px 0; }
.room .big { font-size:46px; margin-bottom:2px; }
.room a.go { font-size:16px; padding:12px 26px; display:inline-block; margin-top:8px; }
.room .sub { color:var(--mut); font-size:13px; margin:10px 0 4px; }
</style></head>
<body>
<div class="room">
 <div class="big">📊</div>
 <h1>Uptime Kuma</h1>
 <div class="sub">your self-hosted status monitor — it keeps running in the background</div>
 <a class="btn go" id="open" href="{{.URL}}">Open dashboard →</a>
 <div class="foot">powered by tshare · protected by Uptime Kuma's own login · link is private — don't repost it</div>{{.Abuse}}
</div>
</body></html>`))

// p2pRecvTmpl is the --p2p transfer page a visitor sees: one row per file
// (a single file, or every RAR volume of a --rar share), each with a direct
// WebRTC DataChannel path (fast — bytes never ride the funnel relay) and the
// standard HTTPS download one click away as fallback.
var p2pRecvTmpl = template.Must(template.New("p2precv").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>{{.Title}}</title>
<style>` + pageCSS + `
.xfer { text-align:center; padding:14px 0 4px; }
.xfer .big { font-size:40px; }
.stat { color:var(--mut); font-size:13px; min-height:20px; text-align:center; margin:8px 0 14px; }
.frow { border:1px solid var(--line); border-radius:12px; background:var(--card); padding:12px 14px; margin:10px 0; }
.frow .nm { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:14px; word-break:break-all; }
.frow .meta { color:var(--mut); font-size:12px; margin:2px 0 8px; }
.frow .acts { display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
.frow .btn { font-size:13px; padding:8px 14px; }
.prog { flex:1 1 140px; height:8px; background:var(--bg); border:1px solid var(--line); border-radius:5px; overflow:hidden; display:none; }
.prog i { display:block; height:100%; width:0%; background:var(--acc); transition:width .15s; }
.fstat { color:var(--mut); font-size:12px; margin-top:6px; min-height:16px; }
.hint { color:var(--mut); font-size:12px; text-align:center; margin-top:14px; }
</style></head>
<body>
<div class="xfer"><div class="big">⚡</div><h1>Direct transfer</h1></div>
<div class="stat" id="stat">checking for the sender…</div>
<div id="rows"></div>
{{if .Multi}}<div class="hint">multi-part archive: download <b>every</b> part into one folder, then open
part1 to extract (unrar / 7-Zip / iZip on iOS) · <a href="__zip">⬇ all parts as one .zip (standard)</a></div>{{end}}
<div class="foot" style="text-align:center">⚡ goes browser-to-browser (fastest); standard rides the share host · link is private</div>{{.Abuse}}
<script>
var ICE = {{.Ice}}, FILES = {{.Files}};
var stat=document.getElementById('stat'), rowsEl=document.getElementById('rows');
var online=false, transfers=0;
function say(t){ stat.textContent=t; }
function sleep(ms){ return new Promise(function(r){ setTimeout(r,ms); }); }
function rand(){ var a=new Uint8Array(12); crypto.getRandomValues(a);
  return Array.from(a,function(b){return b.toString(16).padStart(2,'0');}).join(''); }
function fmt(n){ if(n<1048576) return (n/1024).toFixed(0)+' KB';
  if(n<1073741824) return (n/1048576).toFixed(1)+' MB'; return (n/1073741824).toFixed(2)+' GB'; }
async function post(ep,body){ return fetch('__rtc/'+ep,{method:'POST',
  headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):'{}'}); }
FILES.forEach(function(f){
  var row=document.createElement('div'); row.className='frow';
  row.innerHTML='<div class="nm"></div><div class="meta"></div>'+
    '<div class="acts"><button class="btn p2pbtn" disabled>⚡ Direct P2P</button>'+
    '<a class="btn sec" href="'+encodeURIComponent(f.n)+'?dl=1">standard</a>'+
    '<div class="prog"><i></i></div></div><div class="fstat"></div>';
  row.querySelector('.nm').textContent=f.n;
  row.querySelector('.meta').textContent=fmt(f.s);
  rowsEl.appendChild(row);
  row.querySelector('.p2pbtn').onclick=function(){ startP2P(f, row); };
});
(function watchPresence(){
  fetch('__rtc/presence').then(function(r){return r.json();}).then(function(j){
    online = !!j.online;
    document.querySelectorAll('.p2pbtn').forEach(function(b){
      if(!b.dataset.busy) b.disabled = !online;
    });
    if (!transfers) say(online ? 'sender online — ready for direct P2P' :
      'sender tab not responding — retrying… (or use the standard downloads)');
  }).catch(function(){}).then(function(){ setTimeout(watchPresence, 4000); });
})();
async function startP2P(f, row){
  var btn=row.querySelector('.p2pbtn'), bar=row.querySelector('.prog i'),
      prog=row.querySelector('.prog'), fstat=row.querySelector('.fstat');
  btn.disabled=true; btn.dataset.busy='1'; transfers++;
  var writer=null, parts=null;
  try{
    if (window.showSaveFilePicker) {                       // stream to disk
      var h = await showSaveFilePicker({suggestedName:f.n});
      writer = await h.createWritable();
    } else {
      if (f.s > 1500000000) { fstat.textContent='too big for in-memory receive here — use standard (or --rar smaller parts)'; btn.disabled=false; delete btn.dataset.busy; transfers--; return; }
      parts = [];
    }
  }catch(e){ btn.disabled=false; delete btn.dataset.busy; transfers--; return; } // picker cancelled
  var sid = rand(), got = 0, t0 = Date.now(), connected = false, done = false;
  var pc = new RTCPeerConnection({iceServers:ICE});
  pc.onicecandidate = function(e){ if(e.candidate) post('msg?sid='+sid+'&from=b',{t:'cand',c:e.candidate}); };
  pc.ondatachannel = function(e){
    var dc = e.channel; dc.binaryType='arraybuffer'; connected = true;
    prog.style.display='block'; fstat.textContent='connected — receiving…';
    dc.onmessage = async function(ev){
      if (typeof ev.data === 'string') {
        var m = JSON.parse(ev.data);
        if (m.t === 'eof') {
          done = true;
          if (writer) await writer.close();
          else { var blob=new Blob(parts); var a=document.createElement('a');
                 a.href=URL.createObjectURL(blob); a.download=f.n; a.click(); }
          post('msg?sid='+sid+'&from=b',{t:'ack'});
          post('done?sid='+sid);
          bar.style.width='100%';
          fstat.textContent='✓ done — '+fmt(got)+' in '+((Date.now()-t0)/1000).toFixed(1)+'s';
          transfers--; dc.close(); pc.close();
        }
        return;
      }
      got += ev.data.byteLength;
      if (writer) await writer.write(ev.data); else parts.push(ev.data);
      var pct = f.s>0 ? Math.min(100, got*100/f.s) : 0;
      bar.style.width = pct+'%';
      var mbps = got/1048576/((Date.now()-t0)/1000);
      fstat.textContent = fmt(got)+' / '+fmt(f.s)+'  ·  '+mbps.toFixed(1)+' MB/s';
    };
  };
  await post('hello?sid='+sid+'&f='+encodeURIComponent(f.n));
  fstat.textContent='waiting for direct connection…';
  setTimeout(function(){ if(!connected && !done){ fstat.textContent='no direct path (hard NAT both sides?) — use the standard download'; btn.disabled=false; delete btn.dataset.busy; transfers--; } }, 20000);
  while (!done) {                                          // signaling poll
    var r = await fetch('__rtc/msg?sid='+sid+'&as=b&wait=1');
    if (r.status === 204) continue;
    if (!r.ok) { await sleep(1000); continue; }
    var m = await r.json();
    if (m.t === 'offer') {
      await pc.setRemoteDescription(m.sdp);
      var ans = await pc.createAnswer(); await pc.setLocalDescription(ans);
      post('msg?sid='+sid+'&from=b',{t:'answer',sdp:pc.localDescription});
    } else if (m.t === 'cand') {
      try { await pc.addIceCandidate(m.c); } catch(e){}
    }
  }
}
</script>
</body></html>`))

// p2pSendTmpl runs in the auto-opened LOCAL tab on the sharer's machine: it
// long-polls for receivers, streams the file from loopback into a DataChannel
// per receiver, and heartbeats presence so receiver pages can show ⚡.
var p2pSendTmpl = template.Must(template.New("p2psend").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>tshare p2p sender</title>
<style>` + pageCSS + `
.hd { text-align:center; padding:14px 0 4px; }
.fn { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; background:var(--card); border:1px solid var(--line); border-radius:8px; padding:4px 10px; display:inline-block; }
.warn { color:var(--mut); font-size:13px; text-align:center; margin:8px 0 18px; }
ul#xfers { list-style:none; padding:0; max-width:480px; margin:0 auto; }
ul#xfers li { padding:8px 10px; border-bottom:1px solid var(--line); font-size:14px; }
</style></head>
<body>
<div class="hd"><h1>⚡ P2P sender</h1><div class="fn">{{.Name}} · {{.SizeH}}</div></div>
<div class="warn">keep this tab open <b>and visible</b> — it streams the file directly to downloaders.<br>
Safari pauses background tabs (transfers stall until you return); Chrome keeps them running.<br>
closing it disables ⚡ P2P (the standard funnel download keeps working).</div>
<div class="warn" id="health" style="color:var(--acc)">starting…</div>
<ul id="xfers"></ul>
<script>
var ICE = {{.Ice}}, NAME = {{.Name}};
var KEY = new URLSearchParams(location.search).get('k') || '';
var KQ = '?k='+encodeURIComponent(KEY), KA = '&k='+encodeURIComponent(KEY);
var CHUNK = 65536, HIGH = 8388608, LOW = 1048576, active = 0;
var list = document.getElementById('xfers'), health = document.getElementById('health');
function sleep(ms){ return new Promise(function(r){ setTimeout(r,ms); }); }
async function post(ep,body){ return fetch('../__rtc/'+ep+KA,{method:'POST',
  headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); }
function beat(){ fetch('../__rtc/presence'+KQ,{method:'POST'}).catch(function(){}); }
setInterval(beat, 5000); beat();
document.addEventListener('visibilitychange', beat);       // instant beat on tab return
(async function loop(){
  var fails = 0;
  for(;;){
    try{
      if (active >= 4) { await sleep(500); continue; }
      var r = await fetch('../__rtc/next'+KQ+'&wait=1');
      if (r.status === 403 || r.status === 404) {          // stale tab: share restarted
        health.textContent = '✕ this sender tab is STALE — the share was restarted. Close it and use the newly opened one.';
        health.style.color = '#c33'; return;
      }
      fails = 0;
      health.textContent = '● online — waiting for downloaders ('+active+' active)';
      if (r.status === 204) continue;
      if (!r.ok) { await sleep(1500); continue; }
      var j = await r.json();
      if (j.sid) serve(j.sid, j.file || NAME);
    }catch(e){                                             // network hiccup / share gone
      fails++;
      if (fails > 20) { health.textContent = '✕ share unreachable — was it stopped? (Ctrl-C in the terminal ends P2P)'; health.style.color = '#c33'; return; }
      health.textContent = '… reconnecting ('+fails+')';
      await sleep(2000);
    }
  }
})();
async function serve(sid, fname){
  active++;
  var tag = fname.slice(0,24)+' · '+sid.slice(0,6);
  var li = document.createElement('li'); li.textContent = tag+' — connecting…';
  list.appendChild(li);
  var pc = new RTCPeerConnection({iceServers:ICE});
  var dc = pc.createDataChannel('file', {ordered:true});
  dc.binaryType = 'arraybuffer'; dc.bufferedAmountLowThreshold = LOW;
  pc.onicecandidate = function(e){ if(e.candidate) post('msg?sid='+sid+'&from=a',{t:'cand',c:e.candidate}); };
  var finished = false, sent = 0, t0 = 0;
  dc.onopen = async function(){
    try{
      t0 = Date.now();
      dc.send(JSON.stringify({t:'meta',name:fname}));
      var resp = await fetch('../' + encodeURIComponent(fname) + '?raw=1' + KA);
      var reader = resp.body.getReader();
      for(;;){
        var rr = await reader.read();
        if (rr.done) break;
        var buf = rr.value;
        for (var off = 0; off < buf.byteLength; off += CHUNK) {
          while (dc.bufferedAmount > HIGH) {
            await new Promise(function(res){ dc.onbufferedamountlow = res; });
          }
          dc.send(buf.subarray(off, Math.min(off+CHUNK, buf.byteLength)));
          sent += Math.min(CHUNK, buf.byteLength-off);
        }
        var mbps = sent/1048576/((Date.now()-t0)/1000);
        li.textContent = tag+' — '+(sent/1048576).toFixed(1)+' MB · '+mbps.toFixed(1)+' MB/s';
      }
      while (dc.bufferedAmount > 0) { await sleep(100); }
      dc.send(JSON.stringify({t:'eof'}));
      li.textContent = tag+' — ✓ sent '+(sent/1048576).toFixed(1)+' MB';
    }catch(e){ li.textContent = tag+' — ✕ send failed: '+(e && e.message || e); }
    finished = true;
  };
  try{
    var offer = await pc.createOffer(); await pc.setLocalDescription(offer);
    post('msg?sid='+sid+'&from=a',{t:'offer',sdp:pc.localDescription});
    var deadline = Date.now() + 600000;
    while (!finished && Date.now() < deadline) {           // answer/cands (+ack)
      var r = await fetch('../__rtc/msg?sid='+sid+'&as=a&wait=1'+KA);
      if (r.status === 204) continue;
      if (!r.ok) { await sleep(1000); continue; }
      var m = await r.json();
      if (m.t === 'answer') await pc.setRemoteDescription(m.sdp);
      else if (m.t === 'cand') { try { await pc.addIceCandidate(m.c); } catch(e){} }
      else if (m.t === 'ack') break;
    }
  }catch(e){ li.textContent = tag+' — ✕ '+(e && e.message || 'failed'); }
  setTimeout(function(){ pc.close(); }, 3000);
  active--;
}
</script>
</body></html>`))

// callTmpl is the built-in 1:1 WebRTC call (--call): getUserMedia + perfect
// negotiation over the same signaling relay. No MiroTalk needed for a quick
// two-person call — the secret link IS the room.
var callTmpl = template.Must(template.New("call").Parse(`<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><title>tshare call</title>
<style>
:root{color-scheme:dark light}
*{margin:0;box-sizing:border-box}
html,body{height:100%}
body{background:#000;color:#ececf4;font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;flex-direction:column;min-height:100%}
.stage{flex:1;position:relative;display:flex;align-items:center;justify-content:center;overflow:hidden}
video#rv{width:100%;height:100%;object-fit:contain;background:#000}
video#lv{position:absolute;right:14px;bottom:14px;width:26vw;max-width:220px;border-radius:10px;border:1px solid #26263a;background:#101018}
.bar{display:flex;gap:10px;align-items:center;justify-content:center;padding:12px 14px calc(12px + env(safe-area-inset-bottom));border-top:1px solid #23232f;background:#101018}
.bar button{background:#181826;color:#ececf4;border:1px solid #26263a;border-radius:10px;padding:10px 16px;font-size:14px;cursor:pointer}
.bar button.off{background:#3a1820;border-color:#5c2430}
.bar .st{color:#9a9aac;font-size:13px;margin-right:8px}
.abuse{color:#6a6a7c;font-size:11px;text-align:center;padding:4px 12px;opacity:.8}
</style></head>
<body>
<div class="stage"><video id="rv" autoplay playsinline></video><video id="lv" autoplay playsinline muted></video></div>
<div class="bar">
 <span class="st" id="st">joining…</span>
 <button id="mute">🎙 mute</button>
 <button id="cam">🎥 cam</button>
 <button id="bye">⏻ leave</button>
</div>{{.Abuse}}
<script>
var ICE = {{.Ice}}, SID = 'call';
var st=document.getElementById('st'), lv=document.getElementById('lv'), rv=document.getElementById('rv');
function say(t){ st.textContent = t; }
function sleep(ms){ return new Promise(function(r){ setTimeout(r,ms); }); }
async function post(body,role){ return fetch('__rtc/msg?sid='+SID+'&from='+role,{method:'POST',
  headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}); }
(async function(){
  var cr = await fetch('__rtc/claim');
  if (cr.status === 409) { say('call is full (two participants max)'); return; }
  var role = (await cr.json()).role, polite = role === 'b';
  setInterval(function(){ fetch('__rtc/presence?as='+role,{method:'POST'}); }, 5000);
  var stream;
  try { stream = await navigator.mediaDevices.getUserMedia({video:true,audio:true}); }
  catch(e){ say('camera/mic blocked — check permissions (needs HTTPS)'); return; }
  lv.srcObject = stream;
  var pc = new RTCPeerConnection({iceServers:ICE});
  stream.getTracks().forEach(function(t){ pc.addTrack(t, stream); });
  pc.ontrack = function(e){ rv.srcObject = e.streams[0]; say('connected'); };
  pc.onicecandidate = function(e){ if(e.candidate) post({t:'cand',c:e.candidate},role); };
  pc.onconnectionstatechange = function(){
    if (pc.connectionState==='disconnected'||pc.connectionState==='failed') say('peer left / connection lost');
  };
  var makingOffer = false, ignoreOffer = false;
  pc.onnegotiationneeded = async function(){
    try { makingOffer = true; await pc.setLocalDescription();
      post({t:'sdp',sdp:pc.localDescription},role); }
    catch(e){} finally { makingOffer = false; }
  };
  say(role==='a' ? 'waiting for the other side…' : 'connecting…');
  document.getElementById('mute').onclick = function(){
    var t = stream.getAudioTracks()[0]; t.enabled = !t.enabled;
    this.classList.toggle('off', !t.enabled);
  };
  document.getElementById('cam').onclick = function(){
    var t = stream.getVideoTracks()[0]; t.enabled = !t.enabled;
    this.classList.toggle('off', !t.enabled);
  };
  document.getElementById('bye').onclick = function(){
    pc.close(); stream.getTracks().forEach(function(t){ t.stop(); }); say('left the call');
  };
  for(;;){                                                 // signaling poll
    var r = await fetch('__rtc/msg?sid='+SID+'&as='+role+'&wait=1');
    if (r.status === 204) continue;
    if (!r.ok) { await sleep(1000); continue; }
    var m = await r.json();
    if (m.t === 'sdp') {
      var desc = m.sdp;
      var collision = desc.type === 'offer' && (makingOffer || pc.signalingState !== 'stable');
      ignoreOffer = !polite && collision;
      if (ignoreOffer) continue;
      await pc.setRemoteDescription(desc);
      if (desc.type === 'offer') {
        await pc.setLocalDescription();
        post({t:'sdp',sdp:pc.localDescription},role);
      }
    } else if (m.t === 'cand') {
      try { await pc.addIceCandidate(m.c); } catch(e){ if(!ignoreOffer) console.warn(e); }
    }
  }
})();
</script>
</body></html>`))

// hubTmpl is the --hub control panel: a homescreen-style (Add-to-Home-Screen,
// standalone) 2-way remote — upload files to the host, paste a URL for the host
// to grab (web), browse/download/delete the folder (local), and a scratch note.
var hubTmpl = template.Must(template.New("hub").Parse(`<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><title>{{.Title}} · hub</title>
<link rel="manifest" href="manifest.webmanifest">
<link rel="apple-touch-icon" href="apple-touch-icon.png">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="hub">
<meta name="theme-color" content="#4f63ff">
<style>` + pageCSS + `
body{max-width:640px;padding-top:max(20px,env(safe-area-inset-top))}
.apphead{display:flex;align-items:center;gap:12px;margin-bottom:16px}
.apphead .ic{width:44px;height:44px;border-radius:11px;background:var(--acc);display:flex;align-items:center;justify-content:center;color:#fff;font-size:22px;flex:0 0 auto}
.apphead h1{font-size:19px;margin:0}
.apphead .sub{color:var(--mut);font-size:12px}
.tiles{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:18px}
.tile{border:1px solid var(--line);border-radius:14px;background:var(--card);padding:16px;cursor:pointer;text-align:center;user-select:none}
.tile:active{transform:scale(.98)}
.tile .em{font-size:26px}
.tile .lb{font-size:13px;margin-top:6px;font-weight:600}
.panel{border:1px solid var(--line);border-radius:14px;background:var(--card);padding:16px;margin-bottom:16px;display:none}
.panel.on{display:block}
.panel h2{font-size:14px;margin:0 0 10px}
.row{display:flex;gap:8px}
input[type=url],input[type=text],textarea{width:100%;padding:11px 12px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--fg);font:inherit;font-size:15px}
textarea{min-height:90px;resize:vertical}
.drop{border:2px dashed var(--line);border-radius:12px;padding:26px;text-align:center;color:var(--mut)}
.drop.on{border-color:var(--acc);color:var(--acc)}
ul.files{list-style:none;padding:0;margin:10px 0 0}
ul.files li{display:flex;align-items:center;gap:8px;padding:9px 4px;border-bottom:1px solid var(--line);font-size:14px}
ul.files li .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
ul.files li .sz{color:var(--mut);font-size:12px;white-space:nowrap}
ul.files a,ul.files button.x{color:var(--acc);text-decoration:none;background:none;border:none;cursor:pointer;font-size:16px;padding:2px 6px}
.jobs{margin-top:12px}
.job{font-size:12px;color:var(--mut);padding:6px 0;border-top:1px solid var(--line)}
.jbar{height:6px;background:var(--bg);border:1px solid var(--line);border-radius:4px;overflow:hidden;margin-top:4px}
.jbar i{display:block;height:100%;width:0;background:var(--acc);transition:width .2s}
.muted{color:var(--mut);font-size:12px}
</style></head>
<body data-base="{{.Base}}">
<div class="apphead"><div class="ic">⬍</div><div><h1>{{.Title}}</h1><div class="sub">tshare hub · your private 2-way drop</div></div></div>

<div class="tiles">
 <div class="tile" data-panel="up"><div class="em">📤</div><div class="lb">Send files</div></div>
 <div class="tile" data-panel="grab"><div class="em">🌐</div><div class="lb">Grab a URL</div></div>
 <div class="tile" data-panel="files"><div class="em">📁</div><div class="lb">Files</div></div>
 <div class="tile" data-panel="note"><div class="em">📝</div><div class="lb">Note</div></div>
</div>

<div class="panel" id="p-up"><h2>📤 Send files to the host</h2>
 <div class="drop" id="drop">tap to choose, or drop files here</div>
 <input type="file" id="file" multiple style="display:none">
 <div class="muted" id="upstat" style="margin-top:8px"></div>
</div>

<div class="panel" id="p-grab"><h2>🌐 Grab from the web {{if not .YtDlp}}<span class="muted">(direct links only — install yt-dlp for sites/videos)</span>{{end}}</h2>
 <div class="row"><input type="url" id="grabin" placeholder="https://… (page, video, or file)" autocomplete="off">
 <button class="btn" id="grabbtn">Grab</button></div>
 <div class="jobs" id="jobs"></div>
</div>

<div class="panel" id="p-files"><h2>📁 On the host <button class="btn sec" id="refresh" style="float:right;font-size:12px;padding:4px 10px">refresh</button></h2>
 <ul class="files" id="files"></ul>
</div>

<div class="panel" id="p-note"><h2>📝 Shared note</h2>
 <textarea id="note" placeholder="type anything — saved on the host, visible to anyone with this link"></textarea>
 <div class="muted" id="notestat" style="margin-top:6px"></div>
</div>

<div class="foot">private link — don't repost it · Add to Home Screen for an app-like remote</div>{{.Abuse}}
<script>
var B = document.body.dataset.base;
function api(p){ return B + p; }
document.querySelectorAll('.tile').forEach(function(t){
 t.onclick=function(){
  var id=t.dataset.panel, p=document.getElementById('p-'+id);
  var open=p.classList.contains('on');
  document.querySelectorAll('.panel').forEach(function(x){x.classList.remove('on');});
  if(!open){ p.classList.add('on'); if(id==='files') loadFiles(); if(id==='note') loadNote(); }
 };
});
function fmt(n){ if(n<1024)return n+' B'; if(n<1048576)return (n/1024).toFixed(0)+' KB';
 if(n<1073741824)return (n/1048576).toFixed(1)+' MB'; return (n/1073741824).toFixed(2)+' GB'; }

/* ---- upload ---- */
var drop=document.getElementById('drop'), fileIn=document.getElementById('file'), upstat=document.getElementById('upstat');
drop.onclick=function(){ fileIn.click(); };
fileIn.onchange=function(){ send(fileIn.files); };
['dragover','dragenter'].forEach(function(e){ drop.addEventListener(e,function(ev){ev.preventDefault();drop.classList.add('on');}); });
['dragleave','drop'].forEach(function(e){ drop.addEventListener(e,function(ev){ev.preventDefault();drop.classList.remove('on');}); });
drop.addEventListener('drop',function(ev){ if(ev.dataTransfer.files.length) send(ev.dataTransfer.files); });
function send(files){
 if(!files.length) return;
 var fd=new FormData(); for(var i=0;i<files.length;i++) fd.append('f',files[i]);
 var xhr=new XMLHttpRequest(); xhr.open('POST', api('__upload'));
 xhr.upload.onprogress=function(e){ if(e.lengthComputable) upstat.textContent='uploading… '+Math.round(e.loaded*100/e.total)+'%'; };
 xhr.onload=function(){ upstat.textContent = xhr.status<300 ? '✓ sent '+files.length+' file(s)' : '✕ upload failed'; loadFiles(); };
 xhr.onerror=function(){ upstat.textContent='✕ upload failed'; };
 xhr.send(fd);
}

/* ---- grab ---- */
var grabin=document.getElementById('grabin'), grabbtn=document.getElementById('grabbtn'), jobsEl=document.getElementById('jobs');
grabbtn.onclick=doGrab;
grabin.addEventListener('keydown',function(e){ if(e.key==='Enter') doGrab(); });
function doGrab(){
 var u=grabin.value.trim(); if(!u) return;
 var fd=new FormData(); fd.append('url',u);
 fetch(api('__grab'),{method:'POST',body:fd}).then(function(r){
  if(!r.ok) return r.text().then(function(t){ throw new Error(t); });
  return r.json();
 }).then(function(){ grabin.value=''; pollJobs(); }).catch(function(e){ alert('grab: '+e.message); });
}
function pollJobs(){
 fetch(api('__jobs')).then(function(r){return r.json();}).then(function(js){
  jobsEl.innerHTML='';
  var anyRunning=false;
  js.forEach(function(j){
   if(j.status==='running') anyRunning=true;
   var d=document.createElement('div'); d.className='job';
   var head = (j.status==='done'?'✓ ':j.status==='error'?'✕ ':'⏳ ')+ (j.name||j.url);
   if(j.status==='error') head += ' — '+j.err;
   else if(j.status==='done') head += ' · '+fmt(j.size);
   d.textContent=head;
   if(j.status==='running'){ var b=document.createElement('div'); b.className='jbar';
     b.innerHTML='<i style="width:'+(j.pct||0)+'%"></i>'; d.appendChild(b); }
   jobsEl.appendChild(d);
  });
  if(anyRunning){ loadFiles(); setTimeout(pollJobs,1200); }
  else loadFiles();
 }).catch(function(){});
}

/* ---- files ---- */
var filesEl=document.getElementById('files');
document.getElementById('refresh').onclick=loadFiles;
function loadFiles(){
 fetch(api('__list')).then(function(r){return r.json();}).then(function(fs){
  filesEl.innerHTML='';
  if(!fs.length){ filesEl.innerHTML='<li class="muted">empty — send a file or grab a URL</li>'; return; }
  fs.forEach(function(f){
   var li=document.createElement('li');
   var a=document.createElement('a'); a.href=api(encodeURIComponent(f.name))+'?dl=1'; a.textContent='⬇'; a.title='download';
   var nm=document.createElement('span'); nm.className='nm'; nm.textContent=f.name;
   var sz=document.createElement('span'); sz.className='sz'; sz.textContent=f.sizeh;
   var x=document.createElement('button'); x.className='x'; x.textContent='🗑'; x.title='delete';
   x.onclick=function(){ if(!confirm('Delete '+f.name+'?')) return;
     var fd=new FormData(); fd.append('name',f.name);
     fetch(api('__rm'),{method:'POST',body:fd}).then(function(){ loadFiles(); }); };
   li.appendChild(nm); li.appendChild(sz); li.appendChild(a); li.appendChild(x);
   filesEl.appendChild(li);
  });
 }).catch(function(){});
}

/* ---- note ---- */
var noteEl=document.getElementById('note'), noteStat=document.getElementById('notestat'), noteT;
function loadNote(){ fetch(api('__note')).then(function(r){return r.json();}).then(function(j){ noteEl.value=j.note||''; }); }
noteEl.addEventListener('input',function(){ noteStat.textContent='saving…'; clearTimeout(noteT); noteT=setTimeout(function(){
  var fd=new FormData(); fd.append('note',noteEl.value);
  fetch(api('__note'),{method:'POST',body:fd}).then(function(){ noteStat.textContent='✓ saved'; });
},600); });
</script>
</body></html>`))

// mediaTmpl is a minimal, iOS-friendly player page. The media element streams
// from ?raw=1 (Range-served), playsinline keeps iOS from forcing an odd
// fullscreen frame, and the viewport/CSS make it fill the screen responsively.
var mediaTmpl = template.Must(template.New("media").Parse(`<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><title>{{.Name}}</title>
<style>
:root{color-scheme:dark light}
*{margin:0;box-sizing:border-box}
html,body{height:100%}
body{background:#000;color:#ececf4;font:14px/1.5 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
 display:flex;flex-direction:column;min-height:100%}
.stage{flex:1;display:flex;align-items:center;justify-content:center;padding:env(safe-area-inset-top) 12px 12px;overflow:auto}
video,img{max-width:100%;max-height:82vh;width:auto;height:auto;border-radius:10px;background:#000;display:block}
video{width:100%}
audio{width:min(680px,92vw)}
.bar{display:flex;gap:14px;align-items:center;justify-content:center;flex-wrap:wrap;
 padding:12px 14px calc(12px + env(safe-area-inset-bottom));border-top:1px solid #23232f;background:#101018}
.bar .nm{color:#9a9aac;max-width:60vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar a{color:#7d8cff;text-decoration:none;font-weight:600}
.bar a.rep{color:#6a6a7c;font-weight:400;font-size:12px}
.abuse{color:#6a6a7c;font-size:11px;text-align:center;padding:0 12px calc(10px + env(safe-area-inset-bottom));opacity:.8}
.abuse a{color:inherit}
</style></head>
<body>
<div class="stage">
{{if eq .Kind "video"}}
 <video controls playsinline webkit-playsinline preload="metadata" x-webkit-airplay="allow"{{if .Poster}} poster="{{.Poster}}"{{end}}>
  <source src="?raw=1"{{if .Type}} type="{{.Type}}"{{end}}>
  {{range .Tracks}}<track kind="subtitles" src="{{.Src}}" label="{{.Label}}"{{if .Default}} default{{end}}>
  {{end}}your browser can't play this video — <a href="?dl=1">download it</a>.
 </video>
{{else if eq .Kind "audio"}}
 <audio controls preload="metadata">
  <source src="?raw=1"{{if .Type}} type="{{.Type}}"{{end}}>
  your browser can't play this audio — <a href="?dl=1">download it</a>.
 </audio>
{{else}}
 <img src="?raw=1" alt="{{.Name}}">
{{end}}
</div>
<div class="bar"><span class="nm">{{.Name}}</span><a href="?dl=1">⬇ download</a><a class="rep" href="__report">⚑ report</a></div>
{{.Abuse}}
</body></html>`))

type crumb struct{ Name, Href string }
type entryView struct {
	Name, Href, DlHref, Size, Mod, Icon string
	IsDir                               bool
	Img                                 bool // image → eligible for the lightbox
}

func entryIcon(name string, isDir bool) string {
	if isDir {
		return "📁"
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".heic", ".svg", ".tif", ".tiff", ".ico":
		return "🖼"
	case ".mp4", ".webm", ".mov", ".m4v", ".mkv", ".avi":
		return "🎬"
	case ".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac":
		return "🎵"
	default:
		return "📄"
	}
}

// isMedia: types browsers can view/play natively → default to inline.
// (.svg is deliberately excluded: it can carry scripts, so it downloads.)
func isMedia(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif", ".bmp", ".ico", ".tif", ".tiff",
		".mp4", ".webm", ".mov", ".m4v", ".mkv",
		".mp3", ".m4a", ".aac", ".ogg", ".opus", ".wav", ".flac":
		return true
	}
	return false
}

func (s *share) renderDir(w *respRec, rel, abs, urlBase string) {
	if w.status != 0 { // already redirected
		return
	}
	// absolute URLs (include the token) — Tailscale strips the mount prefix,
	// so relative links against the browser's URL are unreliable.
	base := urlBase + "/"
	cur := base
	if rel != "" {
		cur += escPath(rel) + "/"
	}
	var entries []entryView
	if s.mode == "multi" && rel == "" {
		for _, e := range s.roots {
			ev := entryView{Name: e.Name, IsDir: e.IsDir, Icon: entryIcon(e.Name, e.IsDir), Img: !e.IsDir && isImageName(e.Name)}
			if e.IsDir {
				ev.Href = cur + url.PathEscape(e.Name) + "/"
				ev.Size = "—"
			} else {
				ev.Href = cur + url.PathEscape(e.Name)
				ev.DlHref = ev.Href + "?dl=1"
				ev.Size = humanSize(e.Size)
			}
			if fi, err := os.Stat(e.Abs); err == nil {
				ev.Mod = fi.ModTime().Format("2006-01-02 15:04")
			}
			entries = append(entries, ev)
		}
	} else {
		des, err := os.ReadDir(abs)
		if err != nil {
			http.Error(w, "500 cannot list folder", http.StatusInternalServerError)
			return
		}
		for _, de := range des {
			name := de.Name()
			if strings.HasPrefix(name, ".") {
				continue
			}
			ev := entryView{Name: name, IsDir: de.IsDir(), Icon: entryIcon(name, de.IsDir()), Img: !de.IsDir() && isImageName(name)}
			if de.IsDir() {
				ev.Href = cur + url.PathEscape(name) + "/"
				ev.Size = "—"
			} else {
				ev.Href = cur + url.PathEscape(name)
				ev.DlHref = ev.Href + "?dl=1"
				if fi, err := de.Info(); err == nil {
					ev.Size = humanSize(fi.Size())
				}
			}
			if fi, err := de.Info(); err == nil {
				ev.Mod = fi.ModTime().Format("2006-01-02 15:04")
			}
			entries = append(entries, ev)
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})

	title := "shared files"
	if s.mode == "dir" {
		title = filepath.Base(s.roots[0].Abs)
	}
	var crumbs []crumb
	crumbs = append(crumbs, crumb{Name: title, Href: base})
	if rel != "" {
		parts := strings.Split(rel, "/")
		for i, p := range parts {
			crumbs = append(crumbs, crumb{Name: p,
				Href: base + escPath(strings.Join(parts[:i+1], "/")) + "/"})
		}
		title = parts[len(parts)-1]
	}

	hasImg := false
	for _, e := range entries {
		if e.Img {
			hasImg = true
			break
		}
	}
	data := map[string]any{
		"Title": title, "Crumbs": crumbs, "Entries": entries,
		"AllowUp": s.upDir != "" && s.mode == "dir",
		"ZipHref": cur + "__zip", "UploadURL": cur + "__upload",
		"Gallery": hasImg && !s.cfg.NoGallery,
		"Abuse":   s.abuseHTML(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dirTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

func (s *share) renderInbox(w *respRec, urlBase string) {
	if w.status != 0 {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]any{"UploadURL": urlBase + "/__upload", "Abuse": s.abuseHTML()}
	if err := inboxTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

func (s *share) renderRoom(w *respRec) {
	if w.status != 0 {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]any{"RoomName": s.roomName, "RoomURL": s.roomURL, "Abuse": s.abuseHTML()}
	if err := roomTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

func (s *share) renderP2PRecv(w *respRec) {
	if w.status != 0 {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	files := s.p2pFiles()
	type fj struct {
		N string `json:"n"`
		S int64  `json:"s"`
	}
	list := make([]fj, 0, len(files))
	for _, f := range files {
		list = append(list, fj{f.Name, f.Size})
	}
	b, _ := json.Marshal(list)
	data := map[string]any{
		"Title": s.roots[0].Name, "Files": template.JS(b), "Multi": len(files) > 1,
		"Ice": s.iceJSON(), "Abuse": s.abuseHTML(),
	}
	if err := p2pRecvTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

func (s *share) renderP2PSend(w *respRec, r *http.Request) {
	if !s.senderReq(r) {
		http.Error(w, "403", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	sizeH := humanSize(s.roots[0].Size)
	if files := s.p2pFiles(); len(files) > 1 {
		var total int64
		for _, f := range files {
			total += f.Size
		}
		sizeH = fmt.Sprintf("%d parts · %s", len(files), humanSize(total))
	}
	data := map[string]any{
		"Name": s.roots[0].Name, "SizeH": sizeH, "Ice": s.iceJSON(),
	}
	if err := p2pSendTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

func (s *share) renderCall(w *respRec) {
	if w.status != 0 {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := map[string]any{"Ice": s.iceJSON(), "Abuse": s.abuseHTML()}
	if err := callTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

func (s *share) renderHub(w *respRec, urlBase string) {
	if w.status != 0 {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, ytErr := ytBin()
	data := map[string]any{
		"Title": s.roots[0].Name, "Abuse": s.abuseHTML(),
		"YtDlp": ytErr == nil, "Base": urlBase + "/",
	}
	if err := hubTmpl.Execute(w, data); err != nil && !s.cfg.Quiet {
		log.Printf("template: %v", err)
	}
}

func (s *share) serveHubManifest(w *respRec, urlBase string) {
	name := template.JSEscapeString(s.roots[0].Name)
	w.Header().Set("Content-Type", "application/manifest+json")
	fmt.Fprintf(w, `{"name":"tshare hub — %s","short_name":"hub","start_url":"%s/","scope":"%s/","display":"standalone","background_color":"#101018","theme_color":"#4f63ff","icons":[{"src":"apple-touch-icon.png","sizes":"180x180","type":"image/png"},{"src":"icon.png","sizes":"512x512","type":"image/png"}]}`,
		name, urlBase, urlBase)
}

// hubIconPNG is the generated app icon (accent tile + white up/down arrows),
// built once. Pure stdlib image/png — no asset files, no font needed.
var hubIconPNG = sync.OnceValue(func() []byte {
	const sz = 512
	img := image.NewRGBA(image.Rect(0, 0, sz, sz))
	acc := color.RGBA{0x4f, 0x63, 0xff, 0xff}
	white := color.RGBA{0xff, 0xff, 0xff, 0xff}
	rad := 96 // rounded corners
	inCorner := func(x, y int) bool {
		cx, cy := x, y
		if x >= sz-rad {
			cx = sz - rad
		} else if x >= rad {
			return true
		}
		if y >= sz-rad {
			cy = sz - rad
		} else if y >= rad {
			return true
		}
		dx, dy := x-cx, y-cy
		return dx*dx+dy*dy <= rad*rad
	}
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			if inCorner(x, y) {
				img.Set(x, y, acc)
			}
		}
	}
	// two chevrons: up (top) + down (bottom), drawn as thick diagonal strokes
	plot := func(x, y int) {
		for dy := -14; dy <= 14; dy++ {
			for dx := -14; dx <= 14; dx++ {
				if dx*dx+dy*dy <= 196 && x+dx >= 0 && x+dx < sz && y+dy >= 0 && y+dy < sz {
					img.Set(x+dx, y+dy, white)
				}
			}
		}
	}
	stroke := func(x0, y0, x1, y1 int) {
		steps := 220
		for i := 0; i <= steps; i++ {
			t := float64(i) / float64(steps)
			plot(int(float64(x0)+t*float64(x1-x0)), int(float64(y0)+t*float64(y1-y0)))
		}
	}
	stroke(150, 210, 256, 120) // up chevron ╱
	stroke(256, 120, 362, 210) // ╲
	stroke(150, 300, 256, 392) // down chevron ╲
	stroke(256, 392, 362, 300) // ╱
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
})

func serveHubIcon(w *respRec) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(hubIconPNG())
}
