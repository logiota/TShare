#!/usr/bin/env node
// A zero-dependency Node server that also serves the index.html sitting next
// to it — page and API on the SAME share path, from one command:
//
//   tshare host examples                 # detects this file, runs it, shares it
//   tshare host -b --persist examples    # ...and brings it back after a reboot
//
// Four things make a JS app behave well behind tshare:
//
//  1. Take the port from $PORT, else let the OS pick one (port 0). tshare sets
//     $PORT when you pass --port and health-checks it; with no --port it
//     detects whichever port you actually opened — so an ephemeral port is the
//     safest default: two copies can never collide.
//  2. Bind 127.0.0.1. tshare owns the public link and proxies to you over
//     loopback; binding 0.0.0.0 would expose the app on the LAN, unprotected,
//     alongside the secret link.
//  3. Handle SIGTERM. When the share stops, tshare signals the whole process
//     group and waits up to 8s before SIGKILL — closing promptly means no
//     half-finished responses and no delay.
//  4. Keep every URL relative. The app is served under /<token>/, so "/api"
//     escapes the share mount while "api" resolves inside it.

const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');

const root = __dirname; // static files live beside this script
const port = Number(process.env.PORT) || 0; // 0 = OS picks; tshare finds it
const started = new Date();

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
};

const server = http.createServer(async (req, res) => {
  // Path as the app sees it: tshare strips the secret /<token> prefix.
  const { pathname } = new URL(req.url, 'http://localhost');

  if (pathname === '/api/status') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, started, uptimeSeconds: process.uptime() }));
    return;
  }

  // Everything else is a static file next to this script, "/" being index.html.
  const file = path.resolve(root, pathname === '/' ? 'index.html' : '.' + pathname);
  if (file !== root && !file.startsWith(root + path.sep)) {
    res.writeHead(403, { 'content-type': 'text/plain' }); // no ../ escaping the folder
    res.end('forbidden');
    return;
  }
  try {
    const body = await fs.readFile(file);
    res.writeHead(200, { 'content-type': TYPES[path.extname(file)] ?? 'application/octet-stream' });
    res.end(body);
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  }
});

server.listen(port, '127.0.0.1', () =>
  console.log(`listening on http://127.0.0.1:${server.address().port}`));

// Close cleanly when the share stops.
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => server.close(() => process.exit(0)));
}
