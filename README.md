# GooseRelayVPN

[![GitHub](https://img.shields.io/badge/GitHub-GooseRelayVPN-blue?logo=github)](https://github.com/kianmhz/GooseRelayVPN)

**[🇮🇷 راهنمای فارسی (Persian)](README_FA.md)**

A SOCKS5 VPN that tunnels **raw TCP** through a Google Apps Script web app to your own small VPS exit server. To anything on the network path your client only ever talks TLS to a Google IP with `SNI=www.google.com`. Everything in flight is AES-256-GCM encrypted end-to-end — Google never sees plaintext and never holds the key.

> **How it works in simple terms:** Your browser/app talks SOCKS5 to this tool on your computer. The tool wraps every TCP byte in AES-GCM frames and posts them through a Google-facing HTTPS connection to a free Apps Script web app you control. The Apps Script forwards those bytes verbatim to your own VPS, which decrypts and opens the real connection. To the firewall/filter it looks like you're just talking to Google.

> ⚠️ **You need a small VPS for the exit server.** Unlike pure-Apps-Script proxies, this project tunnels raw TCP — anything SOCKS5 can carry — so a real `net.Dial` has to happen somewhere. A small $4/month VPS is plenty. In exchange you can tunnel SSH, IMAP, custom protocols, anything — not just HTTP.

## Support This Project

If you like this project, please consider starring it on GitHub (⭐). It helps the project get discovered.

You can also support the project financially:

- TRX / USDT TRC20:
  `TSxg2WAXYnkoR2UiUTzCxbmqNARAt91aqB`
- BNB / USDT BEP20:
  `0xe7b48d8fd5fbbb4e3fa9a06723a62a88585139ea`
- TON:
  `UQDBzJqzJ5e7uZFPrmarTRSGGbD1UoFK2q5_jWh4D2nnNdUB`

## Important Notes

- Never share `tunnel_key` with anyone. Anyone with this key can use your tunnel/VPS as if they are you.
- A server with public internet access is required. Your exit server must be reachable from Google Apps Script.
- Each Google Apps Script deployment ID has a quota of about 20,000 executions per day, and the quota resets around 10:30 AM Iran time (GMT+3:30).
- You do not need to install a local MITM certificate in this project. The certificate setup in `MasterHttpRelayVPN` is for that project's architecture and is not required here.
- This project was inspired by the idea in the main repository: https://github.com/masterking32/MasterHttpRelayVPN

---

## Disclaimer

GooseRelayVPN is provided for educational, testing, and research purposes only.

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

### Step 1: Get an VPS

You need a Linux VPS with a public IP. Any provider works.

### Step 2: Get the binaries

You need two separate programs:
- **`goose-client`** — runs on **your own computer**. This is what you run every day.
- **`goose-server`** — runs on **your VPS**. You set it up once and leave it running.

**Option A — Download a pre-built release (recommended):**

1. Go to the [Releases page](https://github.com/kianmhz/GooseRelayVPN/releases).
2. Download the right archive for your OS:
   - Windows: `GooseRelayVPN-client-vX.Y.Z-windows-amd64.zip`
   - macOS (Intel): `GooseRelayVPN-client-vX.Y.Z-darwin-amd64.tar.gz`
   - macOS (M1/M2/M3): `GooseRelayVPN-client-vX.Y.Z-darwin-arm64.tar.gz`
   - Linux: `GooseRelayVPN-client-vX.Y.Z-linux-amd64.tar.gz`
   - Android / Termux (arm64): `GooseRelayVPN-client-vX.Y.Z-android-arm64.tar.gz`
3. For the **server**, SSH into your VPS and download the binary for your server OS:
   - **Linux (most common):**
     ```bash
     wget https://github.com/kianmhz/GooseRelayVPN/releases/latest/download/GooseRelayVPN-server-vX.Y.Z-linux-amd64.tar.gz
     tar -xzf GooseRelayVPN-server-vX.Y.Z-linux-amd64.tar.gz
     ```
   - **Windows Server:** download `GooseRelayVPN-server-vX.Y.Z-windows-amd64.zip` from the Releases page and extract it to a folder such as `C:\goose-relay\`. See Step 8 (Windows) below for service setup.

   (Replace `vX.Y.Z` with the latest version number from the Releases page.)

**Option B — Build from source (Go 1.22+):**

```bash
git clone https://github.com/kianmhz/GooseRelayVPN.git
cd GooseRelayVPN
go build -o goose-client ./cmd/client
go build -o goose-server ./cmd/server
```

### Step 3: Generate a secret key

Run this once:

```bash
bash scripts/gen-key.sh
```

Copy the 64-character string it prints. You'll use the **same value** in both the client and server configs. Keep it secret — anyone with this key can use your tunnel.

### Step 4: Configure

Copy the example configs:

```bash
cp client_config.example.json client_config.json
cp server_config.example.json server_config.json
```

Open both files and paste your key into the `tunnel_key` field. Leave `script_keys` empty for now.

`client_config.json`:

```json
{
  "socks_host":  "127.0.0.1",
  "socks_port":  1080,
  "google_host": "216.239.38.120",
  "sni":         "www.google.com",
  "script_keys": ["PASTE_DEPLOYMENT_ID"],
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

### Step 5: Set up the Google Apps Script

This is the free Google-side piece that hides your traffic.

1. Go to [Google Apps Script](https://script.google.com/) and sign in.
2. Click **New project**.
3. Delete the default code and paste everything from [`apps_script/Code.gs`](apps_script/Code.gs).
4. Change this line to your VPS IP:
   ```javascript
   const VPS_URL = 'http://YOUR.VPS.IP:8443/tunnel';
   ```
5. Click **Deploy → New deployment** → set type to **Web app**.
6. Set **Execute as:** Me and **Who has access:** Anyone.
7. Click **Deploy**. A dialog appears showing the **Deployment ID**. Copy that value and paste it into `script_keys`.
8. Paste that ID into `script_keys` in `client_config.json`.

> ⚠️ Every time you edit `Code.gs` you must create a **new deployment** (Deploy → **New deployment**) and update `script_keys`. Just saving the code is not enough.

### Step 6: Open port 8443 on your VPS firewall

The server needs port 8443 to be reachable from the internet. On your VPS run:

```bash
sudo ufw allow 8443/tcp
```

Then verify it works from your own computer (replace with your real VPS IP):

```bash
curl http://YOUR.VPS.IP:8443/healthz
```

You should get an empty response with HTTP 200. If `curl` times out or refuses, also check your **cloud provider's firewall** (called "Security Groups" on AWS/Hetzner, "Firewall Rules" on DigitalOcean/Vultr, etc.) and add an inbound rule for TCP port 8443.

### Step 7: Start the server on your VPS

On your VPS, run the server binary:

```bash
./goose-server -config server_config.json
```

You should see it print the listening address and the healthz/tunnel URLs. Leave this terminal open, or set up the systemd service (Step 8) to keep it running after reboots.

### Step 8: Keep the server running after reboot (systemd)

If you want the exit server to start automatically after a VPS reboot, create a systemd service.

Run on your VPS:

```bash
sudo nano /etc/systemd/system/goose-relay.service
```

Paste this (adjust the path if your binary is in a different location):

```ini
[Unit]
Description=GooseRelayVPN exit server
After=network.target

[Service]
Type=simple
WorkingDirectory=/root
ExecStart=/root/goose-server -config /root/server_config.json
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Then run:

```bash
sudo systemctl daemon-reload
sudo systemctl enable goose-relay
sudo systemctl start goose-relay
sudo systemctl status goose-relay --no-pager
```

### Step 8 (Windows): Keep the server running after reboot (NSSM)

If your VPS runs **Windows Server**, use [NSSM](https://nssm.cc) (Non-Sucking Service Manager) to register `goose-server` as a Windows service instead of systemd. The `goose-server.exe` binary is a plain Go binary — no installer needed.

**1. Open port 8443 in Windows Firewall** (run as Administrator in Command Prompt):
```cmd
netsh advfirewall firewall add rule name="GooseRelayVPN" protocol=TCP dir=in localport=8443 action=allow
```
Also add an inbound TCP/8443 rule in your cloud provider's firewall panel (Security Groups / Firewall Rules).

**2. Download NSSM** from https://nssm.cc/download, extract it, and note the path to `nssm.exe` (e.g. `C:\nssm\win64\nssm.exe`).

**3. Register and start the service** (run as Administrator):
```cmd
C:\nssm\win64\nssm.exe install GooseRelayVPN "C:\goose-relay\goose-server.exe"
C:\nssm\win64\nssm.exe set GooseRelayVPN AppParameters "-config C:\goose-relay\server_config.json"
C:\nssm\win64\nssm.exe set GooseRelayVPN AppDirectory "C:\goose-relay"
C:\nssm\win64\nssm.exe set GooseRelayVPN Start SERVICE_AUTO_START
C:\nssm\win64\nssm.exe start GooseRelayVPN
```

**4. Verify it is running:**
```cmd
C:\nssm\win64\nssm.exe status GooseRelayVPN
curl http://YOUR.VPS.IP:8443/healthz
```

To stop or uninstall later:
```cmd
C:\nssm\win64\nssm.exe stop GooseRelayVPN
C:\nssm\win64\nssm.exe remove GooseRelayVPN confirm
```

### Step 9: Run the client on your computer

```bash
./goose-client -config client_config.json
```

You should see output like this:

```
CLIENT  INFO    GooseRelayVPN client starting
CLIENT  INFO    SOCKS5 proxy: socks5://127.0.0.1:1080
CLIENT  INFO    pre-flight OK: relay healthy, AES key matches end-to-end
CLIENT  INFO    ready: local SOCKS5 is listening on 127.0.0.1:1080
```

The **pre-flight check** runs automatically at startup and verifies that Apps Script is reachable, the VPS is up, and the AES key matches. If it fails, the message tells you what went wrong.

Now set your browser to use SOCKS5 proxy `127.0.0.1:1080`:

- **Firefox:** Settings → Network Settings → Manual proxy → SOCKS5 host `127.0.0.1` port `1080`. Check **Proxy DNS when using SOCKS v5**.
- **Chrome/Edge:** Use an extension like FoxyProxy or SwitchyOmega.
- **System-wide on macOS/Linux:** Set SOCKS5 in network settings.

---

## LAN Sharing (Optional)

By default the client listens on `127.0.0.1:1080` so only your computer can use it. To share with other devices on your local network, set `socks_host` to `0.0.0.0` in `client_config.json` and restart.

> ⚠️ **Security note:** Anyone on your LAN can then proxy through your tunnel and consume your Apps Script quota. Only do this on trusted networks.

---

## Increase capacity with multiple deployments (recommended)

Each Google account's Apps Script deployment is rate-limited to **~20,000 calls/day**. The client polls about once per second when idle, so a single deployment can sustain steady use, but heavy days hit the cap. To go beyond that, deploy `Code.gs` multiple times — under the same Google account or a few different ones — and put all the Deployment IDs into `script_keys`:

```json
{
  "script_keys": [
    "FIRST_DEPLOYMENT_ID",
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
| `sni` | `www.google.com` | SNI presented during the TLS handshake. Accepts a single string or an array — `["www.google.com", "mail.google.com", "accounts.google.com"]` — where each SNI host gets its own connection and throttle bucket, which can multiply available bandwidth in regions that rate-limit per domain name. |
| `script_keys` | — | Array of Apps Script Deployment IDs (no full URL needed). One ID is required; add more to increase both throughput and quota — each additional ID spawns 3 more concurrent poll workers and adds its own ~20,000 req/day quota bucket. |
| `tunnel_key` | — | 64-char hex AES-256 key. Must match the server byte-for-byte. |

### Server (`server_config.json`)

| Field | Default | What it does |
|---|---|---|
| `server_host` | `0.0.0.0` | Host/IP where the exit server binds. |
| `server_port` | `8443` | Port where the exit server listens. Must be reachable from Google's network. |
| `tunnel_key` | — | 64-char hex AES-256 key. Must match the client. |
| `upstream_proxy` | *(optional)* | Route all outbound connections through a local SOCKS5 proxy. Useful when your VPS datacenter IP is blocked by certain sites. Set to `socks5://127.0.0.1:40000` to use Cloudflare WARP (DNS is resolved by the proxy, so target sites see the Cloudflare IP instead of your VPS IP). Leave empty or omit to dial directly. |
| `debug_timing` | `false` | When `true`, logs per-session DNS and TCP dial latency so you can pinpoint where time is going. |

---

## Updating the Apps Script forwarder

If you change `Code.gs` — for example to point at a new VPS IP — you must create a **new deployment** in the Apps Script editor (Deploy → **New deployment**, not just "Manage deployments"). Saving alone does nothing; the live `/exec` URL serves the published version. After redeploying, update `script_keys` in `client_config.json`.

---

## Architecture

```
┌─────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────┐
│ Browser │──►│ goose-client │──►│ Google edge  │──►│ Apps Script │──►│  Your    │──► Internet
│  / App  │◄──│  (SOCKS5)    │◄──│ TLS, fronted │◄──│  doPost()   │◄──│  VPS     │◄──
└─────────┘   └──────────────┘   └──────────────┘   └─────────────┘   └──────────┘
              AES-256-GCM         SNI=www.google     dumb forwarder    decrypt +
              session multiplex   Host=script.…      no plaintext      net.Dial
```

Key invariants:

- **Authentication = AES-GCM tag.** No shared password, no certificates. Frames that fail `Open()` are dropped silently.
- **Apps Script never sees plaintext.** The script is a ~30-line forwarder; the AES key lives only on your machine and the VPS.
- **DNS travels through the tunnel.** The SOCKS5 server uses a no-op resolver; use `socks5h://` so DNS is resolved at the exit, not locally.
- **Long-poll, full-duplex.** The VPS holds each request open for up to 8s waiting for downstream bytes; the client runs **3 concurrent poll workers per deployment ID** — so 3 script keys = 9 workers, 6 keys = 18 workers. More keys means more parallelism, not just more quota. Downstream frames are coalesced in a small (~25 ms) window so streaming workloads send fewer, larger HTTP responses.
- **Health-aware multi-deployment.** When `script_keys` lists more than one deployment, the client picks endpoints in round-robin and exponentially blacklists any that misbehave; one same-poll retry is attempted on a fresh deployment so transient failures don't drop traffic.

### Wire format

- **Frame** (plaintext, inside the sealed batch): `session_id (16) || seq (u64 BE) || flags (u8) || target_len (u8) || target || payload_len (u32 BE) || payload`
- **Batch seal** (AES-GCM): the entire batch is sealed once — `nonce (12 bytes) || AES-GCM(u16 frame_count || [u32 frame_len || frame_bytes] …)` — one nonce and auth-tag per HTTP body, not per frame.
- **HTTP body**: `base64(nonce || ciphertext+tag)`, base64 so it survives Apps Script's `ContentService` text round-trip.

---

## Project Files

```
GooseRelayVPN/
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
│   └── goose-relay.service         # systemd unit template
├── client_config.example.json
└── server_config.example.json
```

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Pre-flight fails: `cannot reach Apps Script` | Your internet connection can't reach Google. Check `google_host` — try a different IP from the 216.239.x.120 range. |
| Pre-flight fails: `HTTP 204 — key mismatch` | The `tunnel_key` in `client_config.json` doesn't match the one in `server_config.json` on the VPS. They must be byte-identical. |
| Pre-flight fails: `Apps Script cannot reach your VPS` | Port 8443 on your VPS is not reachable. Run `sudo ufw allow 8443/tcp` on the VPS and check your cloud provider's firewall rules. |
| Log says `relay returned non-batch payload` | Apps Script returned an HTML page instead of an encrypted batch. Either the deployment in `script_keys` isn't live, or **Who has access** is not set to `Anyone`. Re-deploy (Deploy → **New deployment**) and update `script_keys`. |
| Log says `relay returned HTTP 404 via …` | The Deployment ID in your config doesn't match a live `/exec`. Re-deploy and update the config. |
| Log says `relay returned HTTP 500 via …` | Apps Script can't reach `VPS_URL`. Check the server address in `Code.gs`, confirm the VPS is up, and confirm inbound TCP/8443 is open. `curl http://your.vps.ip:8443/healthz` should return 200. |
| Log says `relay request failed via …: timeout` | Fronted connection to Google is failing. Try a different `google_host` — any 216.239.x.120 served by Google works. |
| Browser hangs on every request | Make sure your browser extension uses SOCKS5 with **DNS through proxy** enabled (not plain SOCKS5). In Firefox, check **Proxy DNS when using SOCKS v5**. |
| `[exit] dial X: ... timeout` on the VPS server logs | The target host blocks datacenter IPs, or your VPS has no outbound connectivity for that port. |
| Cloudflare-protected sites show captchas | Expected. Your VPS's IP is on a datacenter ASN, which Cloudflare's bot scoring often flags. Not a tunnel bug. |
| YouTube buffers a lot at 1080p | Expected. The tunnel adds ~300-800ms per round trip due to Apps Script dispatch overhead. 480p is comfortable. Deploying multiple `script_keys` (see above) helps with sustained throughput. |
| One deployment hits quota mid-session | If `script_keys` has more than one entry, the client automatically blacklists the failing one for a few seconds and keeps going on the others. With only one entry, browsing stops until the quota resets (~10:30 AM Iran time / midnight Pacific). |
| Mismatched AES keys | Symptom: client logs no errors but no traffic flows; VPS logs no `dial ...` lines. Confirm `tunnel_key` is byte-identical in both configs. |

---

## Security Tips

- **Never share `client_config.json` or `server_config.json`** — the AES key is in there and a leaked key means anyone can tunnel through your VPS.
- **Generate a fresh key with `scripts/gen-key.sh`** for every deployment. Don't reuse keys across hosts.
- **AES-GCM is the only authentication.** There's no password, no rate-limiting, no per-user accounting. Treat the key like a server-admin password.
- **Apps Script logs every `doPost` invocation** in Google's dashboard (count and duration only — Apps Script never sees plaintext).
- **Keep `socks_host` on the client at `127.0.0.1`** unless you specifically want LAN sharing.
- **Each Apps Script deployment is rate-limited to ~20,000 calls/day** on free Google accounts.

---

## Special Thanks

Special thanks to [@abolix](https://github.com/abolix) for making this project possible.

## License

MIT
