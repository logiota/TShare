#!/usr/bin/env node
// A minimal, zero-dependency Node server shaped for `tshare run`.
//
//   tshare run -- node examples/hello.js              # share it once
//   tshare run -b --persist -- node examples/hello.js # ...and bring it back after a reboot
//
// Four things make a JS app behave well behind tshare:
//
//  1. Take the port from $PORT, else let the OS pick one (port 0). tshare
//     sets $PORT when you pass --port and health-checks it; with no --port it
//     detects whichever port you actually opened — so an ephemeral port is
//     the safest default: two copies can never collide.
//  2. Bind 127.0.0.1. tshare owns the public link and proxies to you over
//     loopback; binding 0.0.0.0 would expose the app on the LAN, unprotected,
//     alongside the secret link.
//  3. Handle SIGTERM. When the share stops, tshare signals the whole process
//     group and waits up to 8s before SIGKILL — closing promptly means no
//     half-finished responses and no delay.
//  4. Keep every URL relative. The app is served under /<token>/, so "/api"
//     escapes the share mount while "api" resolves inside it.

const http = require('node:http');

const port = Number(process.env.PORT) || 0; // 0 = OS picks; tshare finds it
const started = new Date();

const server = http.createServer((req, res) => {
  // Path as the app sees it: tshare strips the secret /<token> prefix.
  const { pathname } = new URL(req.url, 'http://localhost');

  if (pathname === '/api/status') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, started, uptimeSeconds: process.uptime() }));
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(`<!doctype html><meta charset="utf-8"><title>hello from tshare</title>
<h1>It works 👋</h1>
<p>Node ${process.version}, started ${started.toISOString()}.</p>
<p><a href="api/status">api/status</a> — relative, so it stays inside the share.</p>`);
});

server.listen(port, '127.0.0.1', () =>
  console.log(`listening on http://127.0.0.1:${server.address().port}`));

// Close cleanly when the share stops (and stop accepting during shutdown).
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => server.close(() => process.exit(0)));
}
