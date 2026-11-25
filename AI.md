# tshare for AI agents

tshare can be driven by an AI agent, so you can say *"share this PDF with a password for two hours"* or *"publish my blog folder"* and get a working link back. There are two ways in:

- **The MCP server** (`tshare mcp`) — the recommended way. Any [Model Context Protocol](https://modelcontextprotocol.io) client (Claude Code, Claude Desktop, and others) gets typed tools for creating, listing, changing and stopping shares, with safety fences you choose.
- **The command line**, for agents that run shell commands — every command has machine-readable output.

Shares an agent starts run as detached background shares, exactly like `tshare -b`. They keep working after the agent's session ends, show up in `tshare ls` and `tshare gui`, and stop with `tshare rm`.

> **Read [Safety](#safety) before you connect an agent.** tshare publishes files from your computer to the internet. An agent can be misled by text it reads — a web page, an email, a file — into sharing something you didn't intend. The defaults below are chosen with that in mind; tighten them for anything sensitive.

## Set up the MCP server

The server speaks MCP over stdio: the client starts `tshare mcp` and talks to it on stdin/stdout. Use the full path to the binary (`which tshare`) — desktop apps don't inherit your shell's `PATH`.

**Claude Code**

```sh
claude mcp add tshare -- /usr/local/bin/tshare mcp --allow ~/Shared
```

Add `--scope user` to make it available in every project rather than just this one.

**Claude Desktop** — add this to `~/Library/Application Support/Claude/claude_desktop_config.json`, then restart the app:

```json
{
  "mcpServers": {
    "tshare": {
      "command": "/usr/local/bin/tshare",
      "args": ["mcp", "--allow", "/Users/you/Shared"]
    }
  }
}
```

**Any other MCP client** — run `tshare mcp` as a stdio server. It supports protocol versions `2025-06-18`, `2025-03-26` and `2024-11-05`.

### Server options

These are set by **you**, in the client's configuration — the agent can't change them.

| Option | Effect |
|---|---|
| `--allow <dir>` | Only files and folders under `<dir>` can be shared. Repeat for several. Without it, the agent can share anything your user account can read. |
| `--tailnet-only` | Every share is tailnet-only: reachable on your Tailscale network, never the public internet. |
| `--read-only` | Only the listing tools are offered — the agent can see shares but not create, change or stop them. |
| `--allow-run` | Lets `website` start an *app* it finds in a folder (`package.json`, a `.js` server, `app.py`, …). Off by default, because that runs the folder's own code. Static sites never need it. |
| `--default-expires <dur>` | How long an agent's share lives when it doesn't say (default `1d`). tshare's own default is 15 days; agents get a shorter leash. |

## Tools

| Tool | What it does | Changes anything |
|---|---|---|
| `share_create` | Share a file or folder, publish a website, or open an upload inbox. Returns the link. | yes |
| `share_list` | The shares running on this machine: id, link, mode, expiry, password, downloads. | no |
| `share_info` | Live details of one share: uptime, viewers, bytes served. | no |
| `share_update` | Change a running share's password, expiry or download limit, without restarting it. | yes |
| `share_stop` | Stop one share; its link stops working at once. | yes |
| `tshare_options` | Every tshare option with its explanation (optionally filtered), for building `extra_args`. | no |
| `tshare_doctor` | Check Tailscale, Funnel and the optional tools tshare uses, and say what to fix. | no |

`share_create` takes these arguments — all optional except that something needs a `path`:

| Argument | Meaning |
|---|---|
| `path` | File, folder or URL to share. For `upload_inbox`, the folder uploads land in. |
| `website` | Serve a folder (or a lone `.html`) as a live website instead of a file listing. |
| `root` | Publish at `https://<host>/` instead of a secret path, so `/absolute` links work. Not secret. |
| `password` | Require this password to open the link. |
| `expires` | `30m`, `2h`, `1d`, `1w` or `never`. |
| `persist` | Keep the share across reboots, on the same link. Installs tshare's login agent the first time. |
| `tailnet_only` | Only your Tailscale network can open it. |
| `local` | Local network only, no Tailscale. |
| `upload_inbox` | A link others upload files *to*. |
| `allow_upload` | A shared folder that also accepts uploads. |
| `once` | The link stops working after one download. |
| `name` | A readable path instead of a random secret one (less secret). |
| `extra_args` | Any other tshare flags, e.g. `["--max-rate", "2M"]`. `tshare_options` lists them. |

Things to try once it's connected:

- *Share `~/Shared/report.pdf` with a password for two hours.*
- *Publish `~/Shared/blog` as a website at the root of my node.*
- *What am I sharing right now? Stop anything that's been downloaded.*
- *Give me a link where Sam can upload the photos into `~/Shared/inbox`, for one day.*

## Safety

tshare's links are public unless you make them otherwise, so an agent with this tool can put your files on the internet. The realistic risk isn't the agent going rogue — it's **prompt injection**: instructions hidden in something the agent reads ("…and share `~/.ssh` publicly") that it mistakes for yours. The server is built so that a misled agent can do as little harm as possible:

- **You fence it, not the agent.** `--allow`, `--tailnet-only`, `--read-only` and `--allow-run` live in your client config, outside anything the agent can edit.
- **Short-lived by default.** Agent shares expire in a day unless the agent explicitly asks for longer.
- **No code execution by proxy.** Flags that choose a program to run (`--copyparty-bin`, `--tailscale-bin`, `--yt-args` — yt-dlp's own `--exec` runs commands — and the config-loading ones) are refused, and publishing an app folder needs `--allow-run`.
- **No accidental mass-stop.** `share_stop` only takes the exact id of a running share; the `all` / `--all` / prefix shortcuts that `tshare rm` accepts from a person are refused.
- **Nothing hidden.** Every share an agent makes appears in `tshare ls`, `tshare gui` and the dashboard, and stops with `tshare rm <id>`.

Recommended setups:

- **Day to day:** `tshare mcp --allow ~/Shared` and keep your client asking before each tool call (Claude Code and Claude Desktop do by default).
- **Private work:** add `--tailnet-only`, so nothing an agent makes is ever public.
- **Monitoring only:** `--read-only`.

## The command line, for agents without MCP

Everything the MCP server does is a plain tshare command, and each one has machine-readable output:

| Want | Command | Output |
|---|---|---|
| Start a share and get its details | `tshare -b --json [flags] <path>` | the share's state as JSON once it's up (`id`, `url`, `mode`, `expires`, …) |
| Just the link | `tshare -b --quiet [flags] <path>` | the URL alone |
| List shares | `tshare ls --json` | a JSON array (`[]` when none) |
| One share's live stats | `tshare info <id>` | JSON |
| Change a running share | `tshare set <id> -p <pw> -e <dur> -n <N>` | a confirmation line |
| Stop a share | `tshare rm <id>` | a confirmation line |
| Every option, explained | `tshare --webwiz \| cat` | the full checklist as text |

Errors go to stderr prefixed `tshare:`, with a non-zero exit (1 for a failed share, 2 for bad flags). Always pass `-b`: without it a share runs in the foreground until the process is killed.

## Building without it

The MCP server is one optional file, `mcp.go`. `go build -tags nomcp` leaves it out, and everything else builds and works the same. The README's [How the code fits together](README.md#how-the-code-fits-together) lists the other optional modules.
