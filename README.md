# tshare

Secret-link file sharing and collaboration over [Tailscale Funnel](https://tailscale.com/kb/1311/tailscale-funnel). Single Go binary, stdlib only, macOS + Linux.

Default is the simplest thing possible: `tshare <path>` → one public, unguessable HTTPS link. Everything else is opt-in flags.

## Build

```sh
brew install go        # if needed
cd tshare && go build  # → ./tshare
sudo make install      # optional: /usr/local/bin/tshare
```

Requires Tailscale running, with MagicDNS + HTTPS certs enabled and the `funnel` node attribute ([setup](https://tailscale.com/kb/1223/funnel)). Run `tshare doctor` to check all of it.

## Use

```sh
tshare report.pdf                      # public secret link, Ctrl-C to stop
tshare -p hunter2 -e 24h ~/Designs     # password + 24h expiry, browsable folder UI
tshare --once secrets.env              # link dies after first download
tshare -z -e 1w ~/Photos/trip          # folder as one .zip, lives a week
tshare -u -e 2d                        # inbox: others upload files TO you
tshare -i                              # blackhole inbox: count uploads, keep nothing
tshare --allow-upload -p pw ~/proj     # collaboration: browse + upload, password-gated
tshare a.pdf b.png notes/              # multiple items → combined listing
tshare -t plan.md                      # tailnet-only (tailscale serve, not public)
tshare --max-rate 2M report.iso        # throttle served bandwidth to ~2 MB/s
tshare -b bigfile.iso                  # background; manage with ls / set / rm
tshare ls                              # active shares
tshare rm a1b2c3                       # stop one (rm --all stops all)
tshare extend a1b2c3                   # double the time left (or: extend a1b2c3 3d)
tshare panic                           # kill ALL shares NOW & wipe every token
```

yt-dlp built in — just hand tshare a video URL and it downloads, then shares:

```sh
tshare "https://youtu.be/…"                    # → iOS-ready H.264/AAC mp4 link
tshare -a "https://…"                          # audio only → mp3 (--yt-audio)
tshare --playlist "https://…/playlist?list=…"  # whole playlist → folder share
tshare --yt-format "bv*+ba/b" "https://…"      # custom -f passed to yt-dlp
tshare --yt-args "--cookies cookies.txt" "https://…"   # extra raw yt-dlp args
tshare -b "https://…"                          # download + serve in background
```

For a single video the link and QR print **immediately** — the download runs in the background, and anyone who opens the link early gets a self-refreshing "downloading… N%" page that turns into the file once it's ready. (Playlists, which become a folder, still publish only after the fetch finishes.) The default picks already-MP4/M4A streams and remuxes to a clean MP4 container so it streams and seeks on iOS. A URL is auto-detected; force it with `-Y`. Needs `yt-dlp` on PATH (`brew install yt-dlp`); `tshare doctor` checks for it.

Pipes — share any command's output once it finishes (EOF starts the share):

```sh
yt-dlp -o - "https://…" | tshare - --filename video.mp4   # manual pipe variant
tar czf - project/ | tshare - --filename project.tgz -e 2h
# without --filename the type is sniffed (mp4/webm/mp3/png/zip/…) and auto-named
```

Change a running share without restarting it:

```sh
tshare set a1b2c3 -p newpw      # add/rotate password ( -p "" clears it )
tshare set a1b2c3 -e 3d         # new expiry, counted from now (-e never clears)
tshare set a1b2c3 -n 10         # max downloads
tshare extend a1b2c3            # DOUBLE the time remaining (never = no-op)
tshare extend a1b2c3 2d         # or push the existing expiry out by a fixed amount
tshare info a1b2c3              # live stats (downloads, uploads, uptime) as JSON
```

In a running foreground share you can also just type `-x` (double the time left) or `-x 2d` at the prompt, alongside the existing `-p`/`-e`/`-n` live controls.

Emergency stop: `tshare panic` SIGKILLs **every** running share, tears down all funnel mounts, and wipes all local state (share records, `--persist` records, control sockets) so no token survives — the big red button when a link leaks.

Reach: a normal share is reachable three ways at once — the **public internet** (Funnel), your **tailnet** (same `https://<host>.ts.net/<token>` URL, since Funnel is built on Serve), and your **local network** directly at `http://<lan-ip>:<port>/<token>` (printed as the `lan` line — faster, no internet round-trip). The LAN URL is gated by the same secret token; a direct hit without it 404s. Use `-t` for tailnet-only, `--no-lan` to drop the LAN path, or `-l/--local` for LAN-only with no Tailscale at all.

Media: images, video and audio open in a clean, full-size player page (iOS-friendly — `playsinline`, correct MIME types, byte-range streaming, no quirk-mode mini frame). The raw stream lives at `?raw=1`, `?dl=1` forces download, and folder pages have a ⬇ per row. `--inline` forces in-browser viewing for every type. Non-browser clients (curl, wget) always get the bytes, never the player HTML.

Receiving end needs nothing but a browser or curl:

```sh
curl -OJ  https://mac.tailxxxx.ts.net/<token>/report.pdf      # download
curl -u :pw -F f=@notes.txt https://…/<token>/__upload        # send a file
curl -o all.zip https://…/<token>/__zip                       # folder as zip
```

## Share a running server (v1.10)

`-s` / `--server` reverse-proxies an already-running local server over the funnel — dev servers, notebooks, any `http://localhost:PORT`. A localhost URL is auto-detected as a server (so it's proxied, not downloaded by yt-dlp). tshare's token/password/expiry/limits sit in front; the upstream's `Host` header is rewritten so dev-server host checks pass, and WebSockets/HMR pass through.

```sh
tshare -s http://localhost:8000        # share a server explicitly
tshare http://localhost:5173           # localhost URL → auto-proxied (Vite, etc.)
tshare -s http://localhost:3000 -p pw  # password-gate it
tshare -s http://192.168.1.9:9000      # any reachable host:port with -s
```

Same subpath caveat as `--site`: the app is served under `/<token>/`, so **relative asset paths** work; root-absolute (`/assets/…`) need your dev server's base path set to the share path (pair with `--name`). For Vite/webpack that's `base`/`publicPath`.

## Static websites over Funnel (v1.8)

`--site` (or `--web`) serves a folder as a **live website** instead of a file browser — `index.html` routing, correct content-types, scripts run (no sandbox, no forced download), `404.html` fallback if present, and `ServeContent` caching (Last-Modified/ETag/304). Expiry defaults to **never** since sites are long-term.

```sh
tshare --site ~/blog                 # serve the folder as a website
tshare --site ~/blog/index.html      # same — a lone .html uses its folder as root
tshare --name blog --site ~/blog     # stable path: https://<host>.ts.net/blog/
tshare --site -p hunter2 ~/blog      # password-gated site
```

Funnel caveat (same as any subpath host): the site lives under `https://<host>.ts.net/<token>/`, so **use relative asset paths** (`href="style.css"`, `src="js/app.js"`) — they resolve correctly. Root-absolute paths (`/style.css`) escape the mount and 404; if your generator emits those, set its base URL to the share path and pair with `--name` for a stable prefix. Always share the link **with its trailing slash**.

## Folders run on copyparty (v1.6)

Single-folder browse / upload / inbox shares are handed to [copyparty](https://github.com/9001/copyparty) when it's installed — you get resumable + dedup uploads, thumbnails, a media gallery, search, and WebDAV — **reverse-proxied behind tshare**, so the secret token, password, expiry, byte-cap, access log and probe alerts still apply. copyparty binds to loopback only and runs anonymous; tshare is the gate.

```sh
pip install copyparty            # then folders "just work"
tshare ~/Designs                 # browse via copyparty behind your secret link
tshare --allow-upload ~/proj     # collaborative (read+write)
tshare -u                        # write-only drop-box inbox
tshare --no-copyparty ~/Designs  # force the built-in native folder server
tshare --copyparty-bin ./copyparty-sfx.py ~/x   # explicit binary / sfx
```

tshare's built-in folder server (listing, gallery lightbox, zip-all, native upload + at-rest `--encrypt`) remains as an automatic fallback when copyparty isn't present, and still handles multi-path shares and single files. Native video keeps improving: the player now auto-loads sibling **subtitles** (`movie.srt`/`movie.en.vtt`, `.srt`→WebVTT on the fly) and a **poster** image, on top of the iOS-friendly streaming/seek and `--transcode`/`--hevc`.

## Power features (v1.5)

Change a running foreground share by just **typing options** at it — `-p secret`, `-e 2d`, `-n 5`, `--no-password`, `info`, or `stop` — no second terminal needed (same effect as `tshare set`, which still works from elsewhere).

```sh
tshare --require-identity report.pdf     # funnel link, but tailnet logins only (blocks anon public)
tshare --max-bytes 2G big.iso            # stop after ~2 GB served (1.5× hard ceiling for in-flight)
tshare -u --encrypt                      # inbox that encrypts uploads at rest; prints a key
tshare decrypt -p pass received.txt.enc  # ...decrypt them later
tshare --transcode --hevc clip.mkv       # hardware H.265/HEVC MP4 (VideoToolbox/NVENC), streamable
tshare --265 clip.mkv                     # ^ shortcut: hardware HEVC to a temp file at constant quality
tshare --265 --cq 40 clip.mkv            # tune quality (default CQ 50; see scale note below)
tshare --heif --strip-exif ~/Photos      # HEIC→JPEG for browsers, EXIF stripped; folder gets a lightbox
tshare --progressive - < <(yt-dlp -o - URL)   # serve while it downloads
tshare --live "https://twitch.tv/…"      # live stream, served as bytes arrive
tshare --fetch "https://host/file.bin"   # plain wget-style download, then share
tshare --watch ~/Drop                    # announce new files as they land
tshare --persist ~/site && tshare resume # survive a reboot
tshare -l --lan-https secret.pdf         # LAN-only HTTPS with a self-signed cert
```

`--265` picks the platform's hardware HEVC encoder (VideoToolbox on macOS, NVENC on Linux, libx265 as software fallback), encodes to a temp MP4 tagged `hvc1` so it plays/seeks on iOS, and serves that. Unlike `--transcode --hevc` (fixed ~6 Mbps), it targets a **constant quality** so the bitrate floats with content. Note `--cq` uses each encoder's native scale — on x265/NVENC a *lower* number is higher quality, on Apple VideoToolbox a *higher* number is higher quality — so the same `--cq 50` isn't identical across platforms.

Config & profiles: drop a `~/.config/tshare/config` (see `config.example`) to set defaults and named `--profile` presets. CLI flags always win; `--no-config` ignores it.

Optional org policy: an opt-in `[policy]` section in that same config file sets guard-rails applied at share-creation time — `require_password = true` refuses to start a share without `-p`, and `max_expires = 7d` caps any longer/`never` expiry down to the limit. There is no policy unless you add the section; CLI flags can't override it (that's the point). It's soft governance for a single-operator machine, not a multi-tenant control plane.

```ini
[policy]
require_password = true
max_expires      = 7d
```

Homebrew: `brew install tshare` once the tap is live — `brew tap yourname/tshare && brew install tshare` (the `Formula/tshare.rb` here is what the tap publishes). To build straight from this checkout without a tap: `brew install --build-from-source ./Formula/tshare.rb`.

## All flags

Nice defaults (each individually disableable): the link is **copied to your clipboard** (`--no-copy`), a **terminal QR code** prints when `qrencode` is installed (`--no-qr`; `brew install qrencode`), **desktop notifications** fire for received uploads *and* for invalid/unauthorized access attempts with the caller's IP + attempted URL, throttled against scanners (`--no-notify`), every share **expires after 15 days** unless you pass `-e` (`-e never` = immortal, changeable later via `tshare set`), and Ctrl-C prints a download/upload summary.

| Flag | Effect |
|---|---|
| `-p, --password` | HTTP Basic password (or env `TSHARE_PASSWORD`) |
| `-e, --expires` | auto-stop: `30m`, `2h`, `1d`, `1w`, `never` (default: **15d**) |
| `--filename` | public name for stdin shares / rename a single-file share |
| `-n, --max` / `--once` | stop after N / 1 completed downloads |
| `-u, --upload [dir]` | inbox mode (default `./tshare-inbox`) |
| `-i, --blackhole` | write-only sink: uploads read + counted + notified, **bytes discarded** (nothing on disk) |
| `--allow-upload` | folder share also accepts uploads |
| `--max-rate` | throttle served bandwidth, e.g. `2M` = ~2 MB/s (default: off) |
| `--min-free` | refuse uploads when free disk space drops below this (default **32G**; `0` = off) |
| `--abuse-contact` | show a small-font takedown/abuse line on public share pages (email/URL auto-linked) |
| `-z, --zip` | folder served as one zip stream |
| `-t, --tailnet` | `tailscale serve` instead of funnel (private) |
| `-l, --local` | no tailscale; plain HTTP on LAN only |
| `--no-lan` | don't also expose on the LAN (funnel/serve over loopback only) |
| `-Y, --yt-dlp` | force the argument to be treated as a yt-dlp URL |
| `--yt-audio` / `--yt-format` / `--yt-args` / `--playlist` | yt-dlp controls |
| `-b, --bg` | background; manage via `ls [--json]` / `rm` |
| `--no-qr` / `--no-copy` / `--no-notify` | turn off a default nicety |
| `--open` | also open the link in your browser |
| `--quiet` / `--json` | URL-only / machine-readable output (QR/copy notes go to stderr) |
| `--inline` | view in browser instead of download |
| `--name` | vanity path instead of token (weaker secrecy) |
| `--token-len` | secret length, default 16 (~95 bits) |
| `--max-upload` | per-request upload cap, default 5G |
| `--https-port` | funnel port 443/8443/10000 |
| `--port` | pin local backend port |
| `--tailscale-bin` | CLI path (also env `TAILSCALE`) |

## Security model

- The secret token (95+ bits, `crypto/rand`, constant-time compared) is the gate; add `-p` for a second factor. TLS is Tailscale's, terminated at your node. The LAN path is plain HTTP (token still required), so the token is visible to anyone sniffing your local network — fine for a home/office LAN, but use `-p` or `--no-lan` if that matters.
- Funnel/serve traffic is proxied in by the local tailscaled over loopback; only those loopback requests are trusted to arrive token-less (tailscaled already matched the mount). Any direct connection — every LAN peer, and everything in `--local` — must present the token in the path.
- Path traversal blocked (clean + symlink-resolved confinement); dotfiles inside shared folders are never listed, served, or zipped; upload names sanitized, collisions auto-renamed, size-capped.
- `noindex` headers everywhere; access log shows every request live (404/401/410 flagged with ⚠ and raised as desktop notifications with IP + URL); `tailscale serve` requests show the tailnet identity. Caveat: with Funnel, wrong-*token* URLs are rejected by tailscaled itself and never reach tshare — probe alerts cover bad paths/wrong passwords under a valid link, and everything in `--local` mode.
- Inline-viewed files are served with `Content-Security-Policy: sandbox` (no script execution), and SVG always downloads rather than rendering.
- Each share is its own process + funnel path mount (`/​<token>`), so shares coexist and revoke independently (`tshare rm` kills the process *and* removes the mount, even if the process already died).
- State in `~/.tshare/` (0700). Killed with SIGKILL? The funnel mount can linger pointing at a dead port — `tshare rm <id>` cleans it.

## How it works

`tshare` binds a loopback HTTP server, then runs
`tailscale funnel --bg --https=443 --set-path=/<token> http://127.0.0.1:<port>`
([CLI ref](https://tailscale.com/docs/reference/tailscale-cli/funnel)). Your link is `https://<magicdns-name>/<token>/…`. On exit it runs the same command with `off`. `-t` swaps `funnel` for `serve`.

Note: tailscaled strips the `/<token>` mount prefix before proxying, so requests reach the backend token-less. That's safe — they can only arrive through the secret mount, and the backend binds 127.0.0.1 (in funnel/serve mode the token is therefore not re-checked; local processes on your own machine can hit the loopback port). In `--local` mode the token is enforced strictly. Page links are absolute URLs so the UI works under either proxy behavior.
