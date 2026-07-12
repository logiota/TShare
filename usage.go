//go:build unix

package main

const version = "1.10.0"

const usageText = `tshare v` + version + ` — secret-link file sharing over Tailscale Funnel

USAGE
  tshare [flags] <path> [path...]     share file(s)/folder(s), print secret link
  tshare [flags] <video-url>          download via yt-dlp, then share the file
  tshare -s http://localhost:8000     reverse-proxy a running local server
  tshare -                            share stdin (pipe)
  tshare -u [dir]                     inbox: link where others UPLOAD to you
  tshare -i                           blackhole inbox: accept & count uploads, keep nothing
  tshare --hub [dir]                  homescreen-style 2-way remote: upload + grab URLs + browse
  tshare run [--port N] -- <cmd…>     launch any server (auto-detect its port) & expose it
  tshare host [dir]                   auto-detect the stack in a folder & host it (node/py/docker/php/static)
  tshare tmux                         list servers running in the shared 'tshare' tmux session
  tshare agent install                run 'tshare resume' at login (macOS LaunchAgent; brew-service-ready)
  tshare --rar --p2p big.mkv          split into 1.4 GB RAR volumes → per-part ⚡ P2P
  tshare --room [name]                video-room link (local MiroTalk, auto-started)
  tshare room install                 one-time: install MiroTalk locally from GitHub
  tshare dash                         iOS-home-screen webui of all your shares (auto-password)
  tshare kuma                         expose your Uptime Kuma monitor at the funnel root
  tshare kuma install                 one-time: install Uptime Kuma natively (git + npm)
  tshare --call                       the link IS a 1:1 video call (built-in WebRTC)
  tshare set <id> [-p pw] [-e dur] [-n N]   change options on a RUNNING share
  tshare extend <id> [dur]            push out expiry (no dur = DOUBLE the time left)
  tshare info <id>                    live stats for a running share
  tshare ls [--json]                  list active shares
  tshare rm <id>... | --all           stop share(s), remove funnel mount
  tshare panic                        kill ALL shares NOW & wipe every token/state
  tshare template save/ls/rm          manage reusable flag presets (templates)
  tshare resume                       restart shares saved with --persist
  tshare decrypt [-p pw] <f.enc>...   decrypt files received by an --encrypt inbox
  tshare doctor                       check tailscale / funnel / tools
  tshare version                      print version

  While a foreground share runs you can TYPE options to change it live, e.g.
  "-p secret", "-e 2d", "-x" (double expiry), "-n 5", "--no-password", "info", "stop".

MEDIA
  Images/video/audio play in the browser (streamable, seekable); every folder
  row also has a ⬇ direct-download link. Append ?dl=1 to any file URL to force
  download. --inline forces in-browser viewing for all types. Sibling subtitles
  (movie.srt / movie.en.vtt) and a poster image are auto-added to the player;
  .srt is converted to WebVTT on the fly.

YT-DLP (built in — pass any yt-dlp-supported URL)
  tshare "https://youtube.com/watch?v=…"     download → share an iOS-ready mp4
  tshare -a "https://…"                      audio only → share an mp3
  tshare --playlist "https://…/playlist…"    whole playlist → share as a folder
  tshare --yt-format "bv*+ba" "https://…"    pass a custom -f format to yt-dlp
  tshare --yt-args "--cookies c.txt" "https://…"   extra raw yt-dlp args
  Single-file: the link + QR print immediately; the download runs in the
  background and visitors get a self-refreshing "downloading… N%" page until the
  file is ready (playlists still publish only after the fetch finishes). Default
  picks an H.264/AAC MP4 (remuxed) so it streams + seeks on iOS. Needs yt-dlp on PATH.

PIPES (share the result of any command once it finishes)
  yt-dlp -o - "https://…" | tshare - --filename video.mp4
  tar czf - project/      | tshare - --filename project.tgz -e 2h
  The share starts when stdin hits EOF. Without --filename the type is sniffed
  (mp4/webm/mp3/png/… ) and named automatically.

SECURITY FLAGS
  -p, --password <pw>     require a password (HTTP Basic; curl -u :<pw>)
                          (or set env TSHARE_PASSWORD)
  -e, --expires <dur>     auto-stop after: 30m, 2h, 1d, 1w, never
                          (default: 15d; changeable later via tshare set)
  -n, --max <N>           stop after N completed downloads
      --once              shorthand for -n 1 (burn after reading)
      --max-bytes <sz>    stop after ~this many bytes served (1.5× hard ceiling)
      --max-rate <sz>     throttle served bandwidth, e.g. 2M = ~2 MB/s (default: off)
      --min-free <sz>     refuse uploads when free disk space < this (default 32G; 0=off)
      --require-identity  funnel: require a Tailscale login (blocks anon public)
      --encrypt           encrypt received uploads at rest (AES-256-GCM)
      --abuse-contact <s> show a small-font takedown/abuse line on public pages
      --legal             show a minimal copyright + removal-request line in the
                          banner (opt-in; US law mandates no banner for a personal
                          self-hosted share — this is a courtesy notice, not legal advice)
      --token-len <n>     secret token length, default 16 (~95 bits)
      --name <slug>       vanity path instead of random token (weaker secrecy!)

MODES
  -t, --tailnet           tailnet-only (tailscale serve) instead of public funnel
  -u, --upload [dir]      inbox mode: receive files into dir (default ./tshare-inbox)
  -i, --blackhole         write-only sink: uploads are read, counted & notified,
                          but the bytes are discarded (nothing hits disk). Best
                          over the printed 'lan' URL for a direct throughput test.
      --room [name]       secret link → a token-gated landing page that opens a
                          MiroTalk video room (random room id if none given).
                          -p/-e gate who reaches the join button. With no
                          --mirotalk-url this uses YOUR LOCAL install: one-time
                          "tshare room install", then tshare auto-starts it,
                          mounts it at the funnel root, and stops it on exit.
                          Media is WebRTC P2P; signaling stays on your node.
      --mirotalk-url <u>  use a remote self-hosted instance instead
      --room-name <id>    explicit room id instead of a positional / random one
      --mirotalk-dir/-method/-port   where/how the local install runs
      --call              the secret link IS a built-in 1:1 WebRTC video call —
                          no MiroTalk needed. Two participants, mute/cam/leave.
      --p2p               file OR folder share also offers ⚡ DIRECT browser-to-
                          browser transfer (WebRTC DataChannel): bytes skip the
                          funnel relay entirely when STUN hole-punch succeeds
                          (most NATs, many CGNATs) — much faster for big files.
                          A local sender tab auto-opens (keep it open); the
                          normal HTTPS download stays as one-click fallback.
                          A folder share gives one ⚡ row per file (see --rar).
      --rar               split the file/folder into RAR volumes first, then
                          share the parts (needs rar on PATH). Chunking, not
                          compression (-m0). Pairs with --p2p so each part fits
                          an iPhone's ~1.5 GB in-memory receive.
      --rar-size <sz>     volume size (default 1400M)
      --stun <urls>       ICE STUN servers (comma list; sane public defaults)
      --turn <url>        optional TURN relay (+ --turn-user/--turn-pass) for a
                          guaranteed direct-ish path when hole-punch fails
      --hub [dir]         a homescreen-style 2-way remote (dir default ./tshare-
                          hub): upload files to the host, paste a URL for the
                          host to GRAB (yt-dlp/site or direct file), browse/
                          download/delete the folder, shared note. Add-to-Home-
                          Screen (manifest + icon) makes it app-like on iOS.
                          Grabs of private/loopback addresses are refused (SSRF).
      --allow-upload      folder share also accepts uploads (collaboration)

FOLDER ENGINE
  Single-folder browse/upload/inbox shares are handled by copyparty (resumable
  uploads, dedup, thumbnails, WebDAV) when it's installed — reverse-proxied
  behind tshare's token/password/expiry/limits. Falls back to the native folder
  server automatically. Single files & media stay native (iOS player, transcode).
      --copyparty         force copyparty (error if missing)
      --no-copyparty      always use the native folder server
      --copyparty-bin <p> copyparty binary or copyparty-sfx.py (or env TSHARE_COPYPARTY)
      --copyparty-args    extra raw copyparty args
  -z, --zip               serve a folder as a single .zip download
      --site, --web       serve a folder as a LIVE static website: index.html is
                          rendered, every file opens in-browser (not downloaded),
                          and folders without an index get a browsable listing.
                          Scripts run (no sandbox); expiry defaults to never.
                          Pair with --name for a stable /<name>/ path
  -g, --gamelink          host a GIGA-NET/1-L multiplayer game page in one shot:
                          implies --site --allow-upload, prints + copies a JOIN
                          link for the other player, and auto-opens the page here
                          in host mode — zero clicks (e.g. GigaSnakes). Over
                          funnel/tailnet the game hole-punches via STUN (add
                          --turn for symmetric NAT); -l keeps it LAN-only
  -l, --local             no tailscale: plain HTTP on your LAN (testing/offline)
      --lan-https         --local: serve HTTPS with a self-signed cert
      --no-lan            funnel/serve only — don't also expose on the LAN
                          (by default a share is ALSO reachable directly on your
                          LAN via http://<lan-ip>:<port>/<token>, token-gated)
      --watch             watch a shared folder; announce new files as they land
      --persist           remember this share so 'tshare resume' restarts it
      --profile <name>    use a [name] section from ~/.config/tshare/config
      --template <name>   apply a saved template (== a profile; see: tshare template)
      --no-config         ignore the config file
      --inline            display in browser instead of forcing download
  -Y, --yt-dlp            force treating the argument as a yt-dlp URL
  -a, --yt-audio          yt-dlp: smart audio-only → tagged M4A (cover art)
      --yt-format <f>     yt-dlp: -f format selector
      --yt-args "<args>"  yt-dlp: extra raw args (quoted)
      --playlist          yt-dlp: download the whole playlist (→ folder share)
      --fetch             plain HTTP download (wget-style) instead of yt-dlp
      --progressive       serve while it downloads (stdin or URL)
      --live              live stream: progressive, ends when the source does
  -s, --server            reverse-proxy a running server URL over the funnel
                          (auto for localhost URLs; rewrites Host, passes
                          WebSockets; use relative asset paths under /<token>/)
      --tmux              launch managed servers (run/host/room) as windows of one
                          'tshare' tmux session (attach: tmux attach -t tshare;
                          list: tshare tmux) instead of piped child processes
      --dir <path>        working directory for 'tshare run' (else current dir)

ONE-STOP HOSTING (launch a local server and expose it over the funnel)
  tshare run [flags] -- <command…>   run any command that serves on a port; the
                          port is AUTO-DETECTED (or pin the upstream with --port),
                          then reverse-proxied. e.g.
                            tshare run -- npm start
                            tshare run --port 8000 -- python3 -m http.server 8000
  tshare host [dir]       detect the stack in a folder (package.json→node,
                          compose.yml→docker, app.py/manage.py→python, index.php→php,
                          index.html→static) and host it. Missing runtime? it
                          suggests the brew install — tshare bundles nothing.
  tshare agent install [-- args]   macOS LaunchAgent running 'tshare resume' at
                          login (or your own command). --print to just emit the
                          plist. Shaped for 'brew services start tshare' later.

MEDIA TRANSFORMS (need ffmpeg / sips / imagemagick on PATH)
      --transcode         re-encode video to a clean, streamable MP4
      --hevc              transcode target is H.265/HEVC (hardware-accelerated)
      --265               hardware HEVC to a temp file at constant quality
                          (implies --transcode --hevc; size floats to hit quality)
      --cq <n>            constant-quality for --265 (default 50). Encoder-native
                          scale: x265/NVENC lower=better; Apple VideoToolbox higher=better
      --heif              convert HEIC/HEIF images to JPEG for viewing
      --strip-exif        remove EXIF/metadata from served JPEGs
      --no-gallery        disable the photo lightbox on image folders

OUTPUT & LIFECYCLE
  -b, --bg                run in background (manage with tshare ls / set / rm)
      --filename <name>   public file name (stdin shares & single-file renames)
  -q, --qr                QR code — ON by default when qrencode is installed
  -c, --copy              copy link to clipboard — ON by default
      --no-qr             disable the QR code
      --no-copy           don't touch the clipboard
      --no-open           don't auto-open pages (--p2p sender tab: URL printed instead)
      --no-notify         disable desktop notifications (uploads received;
                          invalid/unauthorized access attempts with IP + URL)
      --open              also open the link in your browser
      --quiet             print only the URL (also mutes QR auto-display)
      --json              print share metadata as JSON
      --max-upload <sz>   per-request upload limit, e.g. 500M, 2G (default 5G)
      --https-port <p>    funnel public port: 443, 8443, 10000 (default 443)
      --port <p>          pin local backend port (default: auto)
      --tailscale-bin <p> path to tailscale CLI (or env TAILSCALE)

EXAMPLES
  tshare report.pdf                      simplest: public secret link
  tshare -p hunter2 -e 24h ~/Designs     password + 24h expiry, browsable folder
  tshare --once secrets.env              link dies after first download
  tshare -z -e 1w ~/Photos/trip          one-week link to a zip of the folder
  tshare -u -e 2d                        2-day upload inbox (drop-box)
  tshare --allow-upload -p s3cret ~/proj shared folder: browse + upload
  tshare --site ~/blog                   serve a static website over funnel
  tshare -s http://localhost:5173        share your running dev server
  tshare "https://youtu.be/…"            yt-dlp download → iOS-ready mp4 link
  tshare -t plan.md                      tailnet-only (not public)
  tshare -b bigfile.iso                  background; later: tshare ls / set / rm
  tshare set a1b2c3 -p newpw -e never    change a running share's options
  tshare rm a1b2c3                       stop one; tshare rm --all stops all
`
