# tshare — security audit (v1.6.0)

Scope: full read-through of `main.go` (auth, path handling, uploads, crypto,
subprocess use, reverse proxy, TLS, logging). This is a self-audit, not a
third-party review, and the code has not yet been compiler- or fuzz-tested.

## Trust model

- The **secret token** in the URL (default 16 chars, ~95 bits from `crypto/rand`,
  constant-time compared) is the primary gate. Optional `-p` password is a second
  factor. TLS for public/tailnet links is terminated by Tailscale.
- **Loopback is trusted.** funnel/serve traffic reaches the backend via the local
  `tailscaled` over 127.0.0.1, and copyparty runs on 127.0.0.1. Any local user or
  process on the host can therefore reach those ports directly, bypassing the
  token. tshare assumes the local machine is trusted.
- Anyone who has the link (and password, if set) is authorized — by design.

## What's done well

- Constant-time token + password comparison (`crypto/subtle`); no modulo bias in
  token generation (`b[i] & 63` over a 64-char alphabet).
- Path traversal is contained: `path.Clean`, `filepath.EvalSymlinks`, and a
  `root` prefix check reject `..` and symlinks that escape the share root;
  dotfiles are hidden from listing, download, and zip.
- Direct (non-proxied) LAN/`--local` requests must present the token — the
  loopback "trusted" shortcut applies only to genuinely proxied requests.
- Inline-served files get `Content-Security-Policy: sandbox` + `X-Content-Type-Options: nosniff`;
  SVG always downloads (never renders); `noindex` + `no-referrer` everywhere.
- Upload filenames are sanitized (no separators, control chars, or `__` prefix);
  per-request body size cap via `MaxBytesReader`; collisions auto-renamed.
- Subprocesses (`yt-dlp`, `ffmpeg`, `copyparty`, `sips`, clipboard) are invoked
  with explicit argv — **no shell**, so no shell-injection from filenames/URLs.
- copyparty is bound to loopback and runs anonymous behind tshare's gate.
- State, control socket, temp, and key material live under `~/.tshare` (0700);
  stdin/fetch/stream temp files are 0600.

## Findings & simple improvements (by priority)

### 1. Weak KDF for password-derived encryption keys — MEDIUM, easy
`resolveEncKey` derives the at-rest key as `SHA-256("tshare-enc:" + password)` with
no salt and no stretching. If `.enc` files leak, a weak password is brute-forced
cheaply. *Simple fix:* fold the per-file salt into derivation and iterate
(PBKDF2 — `golang.org/x/crypto/pbkdf2`, or many rounds of SHA-256 in stdlib), or
when `--encrypt` is used with a password, still prefer the generated 256-bit key
and treat the password only as a wrapper. Already-strong path: the auto-generated
random key.

### 2. Chunked-GCM stream lacks order/truncation binding — MEDIUM, easy
Each 1 MiB chunk is sealed with AES-GCM (good per-chunk integrity), but the format
doesn't authenticate the chunk **count**, so a truncated ciphertext decrypts to a
silently-shortened plaintext. *Simple fix:* pass the chunk index and an
"is-final" flag as GCM **additional authenticated data** (AAD), and refuse to
finish unless the final chunk was seen.

### 3. No password brute-force throttling — MEDIUM, easy
Once the token is known, `-p` password attempts are unlimited. *Simple fix:* add a
small fixed delay on auth failure and/or an in-memory per-IP failure counter that
temporarily 429s. (Token secrecy makes this lower-risk, but it's cheap insurance.)

### 4. Authorization header forwarded to copyparty — LOW, trivial
The reverse proxy passes the client's `Authorization` (tshare password) through to
the copyparty subprocess, which ignores it but may log it. *Simple fix:* delete
`Authorization` (and `Cookie`) in the proxy `Director` before forwarding.

### 5. LAN path is plaintext HTTP by default — LOW, partly mitigated
The default LAN URL serves the token over plain HTTP, sniffable on the local
network. `--lan-https` (self-signed) exists but is opt-in and `--local`-only.
*Simple fix:* print a one-line warning when a token rides plaintext LAN, and/or
allow `--lan-https` alongside funnel by serving TLS on a second port.

### 6. Inbox disk-fill DoS — LOW, easy
The native inbox caps per-request size but not total bytes or file count, so an
anonymous uploader can fill the disk. *Simple fix:* enforce a cumulative inbox
quota / max file count (copyparty has its own limits when it's the engine).

### 7. Missing server timeouts — LOW, trivial
`http.Server` sets only `ReadHeaderTimeout`. *Simple fix:* add `IdleTimeout`
(safe) and a `ReadTimeout` for request bodies; leave `WriteTimeout` unset so large
downloads aren't cut off (or set it generously).

### 8. Coarse byte-cap & download-count races — LOW, by design
`--max-bytes` and `-n` are checked per request, so a few concurrent transfers can
overshoot before the share stops (the 1.5× ceiling bounds this). Acceptable for
the threat model; document it.

### 9. Vanity `--name` shares are logged in full — INFO
`redact()` masks random tokens in logs but not `--name` slugs (which are
user-chosen and weaker anyway). Fine, but note that a vanity path is less secret
and fully logged.

### 10b. HTML renders with scripts by default — INFO, deliberate (v1.9)
A single shared `.html`/`.htm` file, and any file under `--site`, is served as a
real web page **without** the CSP sandbox, so its scripts run (these are almost
always the user's own self-contained apps/sites). Risk is bounded: it's behind
the secret token, it's content the user chose to share, and it runs on a throwaway
`*.ts.net` funnel origin. `.html` *inside* a non-site folder share still downloads
on click, uploaded/inbox content is unaffected, and `?dl=1` forces download. If
you share HTML you don't trust, prefer `--no-... ` download or don't use `--site`.

### 10. Unicode filename spoofing — INFO, easy
`sanitizeName` strips control chars but not bidi/RTL-override or homoglyphs.
*Simple fix:* also strip U+202A–U+202E / U+2066–U+2069 from upload names.

## Suggested quick-win batch
Items 1, 2, 4, 7 are small, self-contained, and meaningfully raise the floor:
salted+stretched KDF, AAD chunk binding, strip proxied auth headers, and add
`IdleTimeout`. 3 and 6 are the next tier if anonymous public exposure is common
in your use.
