# relay-tunnel

[![GitHub](https://img.shields.io/badge/GitHub-relay--tunnel-blue?logo=github)](https://github.com/kianmhz/relay-tunnel)

**[🇮🇷 راهنمای فارسی (Persian)](README_FA.md)**

A SOCKS5 VPN that tunnels **raw TCP** through a Google Apps Script web app to your own small VPS exit server. To anything on the network path your client only ever talks TLS to a Google IP with `SNI=www.google.com`. Everything in flight is AES-256-GCM encrypted end-to-end — Google never sees plaintext and never holds the key.

> **How it works in simple terms:** Your browser/app talks SOCKS5 to this tool on your computer. The tool wraps every TCP byte in AES-GCM frames and posts them through a Google-facing HTTPS connection to a free Apps Script web app you control. The Apps Script forwards those bytes verbatim to your own VPS, which decrypts and opens the real connection. To the firewall/filter it looks like you're just talking to Google.

> ⚠️ **You need a small VPS for the exit server.** Unlike pure-Apps-Script proxies, this project tunnels raw TCP — anything SOCKS5 can carry — so a real `net.Dial` has to happen somewhere. A $4/month DigitalOcean droplet is plenty. In exchange you can tunnel SSH, IMAP, custom protocols, anything — not just HTTP.

## Important Notes

- Never share `tunnel_key` with anyone. Anyone with this key can use your tunnel/VPS as if they are you.
- A server with public internet access is required. Your exit server must be reachable from Google Apps Script.
- Each Google Apps Script deployment ID has a quota of about 20,000 executions per day, and the quota resets around 10:30 AM Iran time (GMT+3:30).
- You do not need to install a local MITM certificate in this project. The certificate setup in `MasterHttpRelayVPN` is for that project's architecture and is not required here.
- This project was inspired by the idea in the main repository: https://github.com/masterking32/MasterHttpRelayVPN

---

## Disclaimer

relay-tunnel is provided for educational, testing, and research purposes only.

- **Provided without warranty:** This software is provided "AS IS", without express or implied warranty, including merchantability, fitness for a particular purpose, and non-infringement.
- **Limitation of liability:** The developers and contributors are not responsible for any direct, indirect, incidental, consequential, or other damages resulting from the use of this project.
- **User responsibility:** Running this project outside controlled test environments may affect networks, accounts, or connected systems. You are solely responsible for installation, configuration, and use.
- **Legal compliance:** You are responsible for complying with all local, national, and international laws and regulations before using this software.
- **Google services compliance:** If you use Google Apps Script with this project, you are responsible for complying with Google's Terms of Service, acceptable-use rules, quotas, and platform policies. Misuse may lead to suspension of your Google account or deployment.
- **License terms:** Use, copying, distribution, and modification are governed by the repository license. Any use outside those terms is prohibited.

---

## How It Works

```
Browser/App
  -> SOCKS5  (127.0.0.1:1080)
  -> AES-256-GCM raw-TCP frames
  -> HTTPS to a Google edge IP   (SNI=www.google.com, Host=script.google.com)
  -> Apps Script doPost()        (dumb forwarder, never sees plaintext)
  -> Your VPS :8443/tunnel       (decrypts, demuxes by session_id, dials target)
  <- Same path in reverse via long-polling
```

Your application sends TCP bytes through the SOCKS5 listener on your computer. The client encrypts each chunk with AES-256-GCM and POSTs batches over a domain-fronted HTTPS connection to your Apps Script web app. The Apps Script is a ~30-line script that forwards the body verbatim to your VPS — it never decrypts and the AES key never touches Google. Your VPS decrypts, dials the real target, and pumps bytes back along the same path. The filter sees only TLS to Google.

---

## Step-by-Step Setup Guide

### Step 1: Get a VPS for the exit server

You need a small Linux VPS that Apps Script's `UrlFetchApp` can reach on TCP/8443. Any provider works; ~$4/month at DigitalOcean is plenty.

- Create an Ubuntu droplet, note its public IP.
- Open inbound TCP/8443 in the droplet's firewall.
- Confirm you can `ssh user@droplet-ip` and that the user has `sudo`.

### Step 2: Get the binaries

Pick one of the two paths below.

**Option A — download a pre-built release (recommended if you don't want to install Go):**

1. Go to the [Releases page](https://github.com/kianmhz/relay-tunnel/releases).
2. Download the archive that matches your computer:
   - Windows: `relay-tunnel-vX.Y.Z-windows-amd64.zip`
   - macOS (Intel): `relay-tunnel-vX.Y.Z-darwin-amd64.tar.gz`
   - macOS (Apple Silicon / M1/M2/M3): `relay-tunnel-vX.Y.Z-darwin-arm64.tar.gz`
   - Linux: `relay-tunnel-vX.Y.Z-linux-amd64.tar.gz`
3. Unzip/untar it. Inside you'll find `relay-client`, `relay-server`, the example configs, and the Apps Script source.

You can also `cd` into that folder and follow the rest of the setup from there — every command below works the same.

**Option B — build from source (Go 1.22+):**

```bash
git clone https://github.com/kianmhz/relay-tunnel.git
cd relay-tunnel
go build -o relay-client ./cmd/client
go build -o relay-server ./cmd/server
```

Or with the included Makefile: `make build` (puts binaries in `bin/`).

### Step 3: Generate an AES-256 key

```bash
bash scripts/gen-key.sh
```

Copy the 64-character hex string. You'll paste the **same value** into both config files in the next step. This is the only authentication between client and server — protect it.

### Step 4: Configure

Copy the example configs:

```bash
cp client_config.example.json client_config.json
cp server_config.example.json   server_config.json
```

Open both and paste the AES hex string into `tunnel_key` (client) and `tunnel_key` (server). Leave `script_key` blank for now - you'll fill it in after Step 5.

`client_config.json`:

```json
{
  "socks_host":  "127.0.0.1",
  "socks_port":  1080,
  "google_host": "216.239.38.120",
  "sni":         "www.google.com",
  "script_key":  "PASTE_DEPLOYMENT_ID_ONLY",
  "script_keys": ["OPTIONAL_SECOND_DEPLOYMENT_ID", "OPTIONAL_THIRD_DEPLOYMENT_ID"],
  "tunnel_key":  "PASTE_OUTPUT_OF_GEN_KEY"
}
```

`server_config.json`:

```json
{
  "server_host": "0.0.0.0",
  "server_port": 8443,
  "tunnel_key":  "SAME_VALUE_AS_CLIENT"
}
```

### Step 5: Deploy the Apps Script forwarder

This is the dumb pipe that disguises your traffic as Google.

1. Open [Google Apps Script](https://script.google.com/) and sign in.
2. Click **New project**.
3. Delete the default code.
4. Open [`apps_script/Code.gs`](apps_script/Code.gs) from this repo, copy everything, paste into the editor.
5. Change this line to your droplet's IP:
   ```javascript
   const DO_URL = 'http://YOUR.DROPLET.IP:8443/tunnel';
   ```
6. Click **Deploy → New deployment** (gear icon → **Web app**).
7. Set:
   - **Execute as:** Me
   - **Who has access:** Anyone
8. Click **Deploy** and copy the deployment ID from the `/exec` URL (the part between `/s/` and `/exec`).
9. Paste that value into `script_key` in `client_config.json`. If you deploy multiple scripts, put extra IDs in `script_keys`.

> ⚠️ **Editing the script doesn't update the live version.** Every time you change `Code.gs` you must create a **new deployment** and update `script_key`/`script_keys` in your client config.

Verify the deployment:

```bash
curl "$YOUR_SCRIPT_URL"
# should print: relay-tunnel forwarder OK
```

### Step 6: Deploy the exit server

A helper script builds a Linux binary, ships it to your droplet, and installs a systemd unit:

```bash
bash scripts/deploy.sh user@your.droplet.ip
```

Verify it's live:

```bash
curl http://your.droplet.ip:8443/healthz   # HTTP 200, empty body
```

### Step 7: Run the client locally

```bash
./relay-client -config client_config.json
```

You should see:

```
[client] SOCKS5 listening on 127.0.0.1:1080
```

### Step 8: Use it

Smoke test:

```bash
curl -x socks5h://127.0.0.1:1080 https://api.ipify.org
```

This should print your **droplet's** IP, not your home IP.

Configure your browser/system to use SOCKS5 `127.0.0.1:1080`. **Use `socks5h://`** (not `socks5://`) so DNS travels through the tunnel — otherwise hostnames get resolved on your local network and the proxy never sees them.

- **Firefox:** Settings → Network Settings → Manual proxy → SOCKS5 host `127.0.0.1` port `1080`. Check **Proxy DNS when using SOCKS v5**.
- **Chrome/Edge:** Use a proxy-switching extension (FoxyProxy, SwitchyOmega). Native OS proxy settings don't speak SOCKS5 with remote DNS cleanly.
- **System-wide on macOS/Linux:** SOCKS5 proxy in network settings.

---

## LAN Sharing (Optional)

By default the client listens on `127.0.0.1:1080` so only your computer can use it. To share with other devices on your local network, set `socks_host` to `0.0.0.0` in `client_config.json` and restart.

> ⚠️ **Security note:** Anyone on your LAN can then proxy through your tunnel and consume your Apps Script quota. Only do this on trusted networks.

---

## Increase capacity with multiple deployments (recommended)

Each Google account's Apps Script deployment is rate-limited to **~20,000 calls/day**. The client polls about once per second when idle, so a single deployment can sustain steady use, but heavy days hit the cap. To go beyond that, deploy `Code.gs` multiple times — under the same Google account or a few different ones — and put all the Deployment IDs into `script_keys`:

```json
{
  "script_key":  "PRIMARY_DEPLOYMENT_ID",
  "script_keys": [
    "SECOND_DEPLOYMENT_ID",
    "THIRD_DEPLOYMENT_ID"
  ]
}
```

What the client does for you automatically:

- **Round-robin** across all configured deployments.
- **Health-aware blacklist** — if one starts failing, the client backs off from it (3 s, 6 s, 12 s, … up to ~48 s) and keeps using the others.
- **Same-poll failover** — if a poll fails on one deployment, the same payload is retried on another within the same poll cycle, so no traffic is lost during transient quota or 5xx events.

> 💡 All deployments must use **the same `tunnel_key`** because they all forward to the same VPS, which only has one AES key. You don't need to change anything on the VPS when you add more deployments.

> 💡 You can paste either just the Deployment ID (the part between `/s/` and `/exec`) or the full `/exec` URL — the client extracts the ID either way.

---

## Configuration

### Client (`client_config.json`)

| Field | Default | What it does |
|---|---|---|
| `socks_host` | `127.0.0.1` | Host/IP for the local SOCKS5 listener. Set to `0.0.0.0` for LAN sharing. |
| `socks_port` | `1080` | Port for the local SOCKS5 listener. |
| `google_host` | `216.239.38.120` | Google edge IP/host to dial (port is fixed to `443`). |
| `sni` | `www.google.com` | SNI presented during TLS handshake. |
| `script_key` | — | Primary Apps Script deployment ID (no full URL needed). |
| `script_keys` | — | Optional extra deployment IDs for health-aware load balancing and quota spreading. |
| `tunnel_key` | — | 64-char hex AES-256 key. Must match the server byte-for-byte. |

### Server (`server_config.json`)

| Field | Default | What it does |
|---|---|---|
| `server_host` | `0.0.0.0` | Host/IP where the exit server binds. |
| `server_port` | `8443` | Port where the exit server listens. Must be reachable from Google's network. |
| `tunnel_key` | — | 64-char hex AES-256 key. Must match the client. |

---

## Updating the Apps Script forwarder

If you change `Code.gs` - for example to point at a new droplet IP - you must create a **new deployment** in the Apps Script editor (Deploy -> **New deployment**, not just "Manage deployments"). Saving alone does nothing; the live `/exec` URL serves the published version. After redeploying, update `script_key`/`script_keys` in `client_config.json`.

---

## Architecture

```
┌─────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────┐
│ Browser │──►│ relay-client │──►│ Google edge  │──►│ Apps Script │──►│  Your    │──► Internet
│  / App  │◄──│  (SOCKS5)    │◄──│ TLS, fronted │◄──│  doPost()   │◄──│  VPS     │◄──
└─────────┘   └──────────────┘   └──────────────┘   └─────────────┘   └──────────┘
              AES-256-GCM         SNI=www.google     dumb forwarder    decrypt +
              session multiplex   Host=script.…      no plaintext      net.Dial
```

Key invariants:

- **Authentication = AES-GCM tag.** No shared password, no certificates. Frames that fail `Open()` are dropped silently.
- **Apps Script never sees plaintext.** The script is a ~30-line forwarder; the AES key lives only on your machine and the VPS.
- **DNS travels through the tunnel.** The SOCKS5 server uses a no-op resolver; use `socks5h://` so DNS is resolved at the exit, not locally.
- **Long-poll, full-duplex.** The VPS holds each request open for 8s waiting for downstream bytes; the client reposts as soon as it returns. Two HTTP exchanges in flight at once give a full-duplex pipe. Downstream frames are coalesced in a small (~25 ms) window so streaming workloads send fewer, larger HTTP responses.
- **Health-aware multi-deployment.** When `script_keys` lists more than one deployment, the client picks endpoints in round-robin and exponentially blacklists any that misbehave; one same-poll retry is attempted on a fresh deployment so transient failures don't drop traffic.

### Wire format

- **Frame** (plaintext, before AES-GCM): `session_id (16) || seq (u64 BE) || flags (u8) || target_len (u8) || target || payload_len (u32 BE) || payload`
- **Envelope** (AES-GCM): `nonce (12) || ciphertext+tag`. Per-frame nonce, empty AAD.
- **HTTP body**: `[u16 frame_count] [u32 frame_len][envelope] ...`, then base64-encoded so it survives Apps Script's `ContentService` text round-trip.

---

## Project Files

```
relay-tunnel/
├── cmd/
│   ├── client/main.go              # Entry point: SOCKS5 listener + carrier loop
│   └── server/main.go              # Entry point: VPS HTTP handler
├── internal/
│   ├── frame/                      # Wire format, AES-GCM seal/open, batch packer
│   ├── session/                    # Per-connection state, seq counters, rx/tx queues
│   ├── socks/                      # SOCKS5 server + VirtualConn (net.Conn adapter)
│   ├── carrier/                    # Long-poll loop + domain-fronted HTTPS client
│   ├── exit/                       # VPS HTTP handler: decrypt, demux, dial upstream
│   └── config/                     # JSON config loaders
├── apps_script/
│   └── Code.gs                     # ~30-line dumb forwarder
├── scripts/
│   ├── gen-key.sh                  # openssl rand -hex 32
│   ├── deploy.sh                   # Build + scp + systemd install on the VPS
│   └── relay-tunnel.service        # systemd unit template
├── client_config.example.json
└── server_config.example.json
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Log says `decode batch: ... base64 ...` | Apps Script returned an HTML page instead of an encrypted batch. Either the deployment in `script_key`/`script_keys` isn't live, or **Who has access** is not set to `Anyone`. Re-deploy (Deploy → **New deployment**) and update `script_key`/`script_keys` in `client_config.json`. |
| Log says `relay returned HTTP 404 via …` | Same root cause as above — the deployment ID in your config doesn't match a live `/exec`. Re-deploy and update the config. |
| Log says `relay returned HTTP 500 via …` | Apps Script can't reach `DO_URL`. Check the IP in `Code.gs`, confirm the VPS is up, and confirm inbound TCP/8443 is open. `curl http://your.vps.ip:8443/healthz` should return 200. |
| Log says `relay request failed via …: timeout` | Fronted connection to Google is failing. Try a different `google_host` — any 216.239.x.120 served by Google works. |
| Browser hangs on every request | You're using `socks5://` instead of `socks5h://`. The non-`h` form resolves DNS locally and the proxy gets called with raw IPs. |
| `[exit] dial X: ... timeout` on the VPS server logs | The target host blocks datacenter IPs, or your VPS has no outbound connectivity for that port. |
| Cloudflare-protected sites show captchas | Expected. Your VPS's IP is on a datacenter ASN (DigitalOcean = AS14061), which Cloudflare's bot scoring flags. Not a tunnel bug. |
| YouTube buffers a lot at 1080p | Expected. The tunnel adds ~300-800ms per round trip due to Apps Script dispatch overhead. 480p is comfortable. Deploying multiple `script_keys` (see above) helps with sustained throughput. |
| One deployment hits quota mid-session | If you have other entries in `script_keys`, the client automatically blacklists the failing one for a few seconds and keeps going on the others. With only one `script_key`, browsing stops until the quota resets (10:30 AM Iran time / midnight Pacific). |
| Mismatched AES keys (`tunnel_key`) | Symptom: client logs no errors but no traffic flows; VPS logs `dial ...` lines never appear. Confirm `tunnel_key` is byte-identical in both configs. |

---

## Security Tips

- **Never share `client_config.json` or `server_config.json`** — the AES key is in there and a leaked key means anyone can tunnel through your VPS.
- **Generate a fresh key with `scripts/gen-key.sh`** for every deployment. Don't reuse keys across hosts.
- **AES-GCM is the only authentication.** There's no password, no rate-limiting, no per-user accounting. Treat the key like a server-admin password.
- **Apps Script logs every `doPost` invocation** in Google's dashboard (count and duration only — Apps Script never sees plaintext).
- **Keep `socks_host` on the client at `127.0.0.1`** unless you specifically want LAN sharing.
- **Each Apps Script deployment is rate-limited to ~20,000 calls/day** on free Google accounts.

---

## License

MIT
