# GooseRelayVPN

[![GitHub](https://img.shields.io/badge/GitHub-GooseRelayVPN-blue?logo=github)](https://github.com/kianmhz/GooseRelayVPN)

**[🇮🇷 راهنمای فارسی (Persian)](README_FA.md)**

A SOCKS5 VPN that tunnels **raw TCP** through a Google Apps Script web app to your own small VPS exit server. To anything on the network path your client only ever talks TLS to a Google IP with one of your configured Google SNI hosts. Everything in flight is AES-256-GCM encrypted end-to-end — Google never sees plaintext and never holds the key.

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
- Google Apps Script URL Fetch quota is about 20,000 calls/day for consumer accounts and is shared by all deployments under the same Google account; Google documents the reset as 24 hours after first use.
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
  -> Zstd-compressed + AES-256-GCM frame batches
  -> HTTPS to a Google edge IP   (configured Google SNI, Host=script.google.com)
  -> Apps Script doPost()        (dumb forwarder, never sees plaintext)
  -> Your VPS :8443/tunnel       (decrypts, demuxes by session_id, dials target)
  <- Same path in reverse via long-polling
```

Your application sends TCP bytes through the SOCKS5 listener on your computer. The client groups them into batches of frames, **Zstandard-compresses** each batch (for compressible traffic such as plain HTTP or JSON APIs this can reduce request/response body size and make large Apps Script bodies safer), then seals the whole batch under a single **AES-256-GCM** envelope and POSTs it over a domain-fronted HTTPS connection to your Apps Script web app. The Apps Script is a small forwarder that validates obvious non-tunnel junk and forwards valid encrypted bodies verbatim to your VPS — it never decrypts and the AES key never touches Google. Your VPS decrypts, dials the real target, and pumps bytes back along the same path. The filter sees only TLS to Google.

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
   - Windows x86_64: `GooseRelayVPN-client-vX.Y.Z-windows-amd64.zip`
   - Windows ARM64: `GooseRelayVPN-client-vX.Y.Z-windows-arm64.zip`
   - macOS (Intel): `GooseRelayVPN-client-vX.Y.Z-darwin-amd64.tar.gz`
   - macOS (M1/M2/M3): `GooseRelayVPN-client-vX.Y.Z-darwin-arm64.tar.gz`
   - Linux x86_64: `GooseRelayVPN-client-vX.Y.Z-linux-amd64.tar.gz`
   - Linux ARM64: `GooseRelayVPN-client-vX.Y.Z-linux-arm64.tar.gz`
   - Linux ARMv7: `GooseRelayVPN-client-vX.Y.Z-linux-armv7.tar.gz`
   - Android / Termux (arm64): `GooseRelayVPN-client-vX.Y.Z-android-arm64.tar.gz`
3. For the **server**, SSH into your VPS and download the binary for your server OS:
   - **Linux x86_64 / amd64 (most common):**
     ```bash
     VERSION=vX.Y.Z
     wget https://github.com/kianmhz/GooseRelayVPN/releases/download/$VERSION/GooseRelayVPN-server-$VERSION-linux-amd64.tar.gz
     tar -xzf GooseRelayVPN-server-$VERSION-linux-amd64.tar.gz
     ```
     Use `linux-arm64` or `linux-armv7` instead if your VPS is ARM-based.
   - **Windows Server:** download `GooseRelayVPN-server-vX.Y.Z-windows-amd64.zip` or `GooseRelayVPN-server-vX.Y.Z-windows-arm64.zip` from the Releases page and extract it to a folder such as `C:\goose-relay\`. See Step 8 (Windows) below for service setup.

   (Replace `vX.Y.Z` with the latest version number from the Releases page.)

> 💡 **If the Releases page doesn't open**, you can download directly using these links (replace `vX.Y.Z` with the latest version):
> - **Client — Windows:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-windows-amd64.zip`
> - **Client — macOS (Apple Silicon):** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-darwin-arm64.tar.gz`
> - **Client — macOS (Intel):** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-darwin-amd64.tar.gz`
> - **Client — Linux x86_64:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-linux-amd64.tar.gz`
> - **Client — Linux ARM64:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-linux-arm64.tar.gz`
> - **Client — Android/Termux:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-android-arm64.tar.gz`
> - **Server — Linux:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-server-vX.Y.Z-linux-amd64.tar.gz`

**Option B — Build from source (Go 1.25+; Go 1.26.3 recommended) — not recommended, may be unstable:**

```bash
git clone https://github.com/kianmhz/GooseRelayVPN.git
cd GooseRelayVPN
go build -o goose-client ./cmd/client
go build -o goose-server ./cmd/server
```

**Option C — Run only the server with Docker (GHCR):**

If you prefer containers on your VPS, you can run `goose-server` directly from GHCR:

```bash
docker pull ghcr.io/kianmhz/gooserelayvpn-server:latest
```

### Step 3: Generate a secret key

Run this once:

```bash
openssl rand -hex 32
```

Copy the 64-character string it prints. You'll use the **same value** in both the client and server configs. Keep it secret — anyone with this key can use your tunnel.

### Step 4: Configure

Copy the example configs:

```bash
cp client_config.example.json client_config.json
cp server_config.example.json server_config.json
```

Open both files and paste your key into the `tunnel_key` field. Do not start the client yet; Step 5 gives you the Apps Script Deployment ID to put into `script_keys`.

`client_config.json`:

```json
{
  "socks_host":  "127.0.0.1",
  "socks_port":  1080,
  "google_host": "216.239.38.120",
  "sni":         ["www.google.com", "mail.google.com", "accounts.google.com"],
  "script_keys": [],
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
4. Change this line to your VPS IP. Keep `8443` unless `server_config.json` uses a different `server_port`:
   ```javascript
   const RELAY_URLS = ['http://YOUR.VPS.IP:8443/tunnel'];
   ```
5. Click **Deploy → New deployment** → set type to **Web app**.
6. Set **Execute as:** Me and **Who has access:** Anyone.
7. Click **Deploy**. A dialog appears showing the **Deployment ID**. Copy that value and paste it into `script_keys`.
8. Paste that ID into `script_keys` in `client_config.json`.

> ⚠️ Every time you edit `Code.gs`, saving alone is not enough. Either create a new deployment and update `script_keys`, or create a new version and edit the existing web-app deployment to use that version if you want to keep the same Deployment ID.

### Step 6: Open port 8443 on your VPS firewall

The server needs port 8443 to be reachable from the internet. On your VPS run:

```bash
sudo ufw allow 8443/tcp
```

You will verify this after starting the server in Step 7. If the check there times out or refuses, also check your **cloud provider's firewall** (called "Security Groups" on AWS/Hetzner, "Firewall Rules" on DigitalOcean/Vultr, etc.) and add an inbound rule for TCP port 8443.

### Step 7: Start the server on your VPS

On your VPS, run the server binary:

**Linux:**
```bash
./goose-server -config server_config.json
```

**Windows Server:**
```cmd
.\goose-server.exe -config server_config.json
```

You should see it print the listening address and the healthz/tunnel URLs. Leave this terminal open, or set up the systemd/NSSM service (Step 8) to keep it running after reboots.

**Docker (GHCR image):**

> ⚠️ **Important:** The container does **not** auto-generate `server_config.json`. You must create and edit `server_config.json` first (with your own `tunnel_key`), then start the container.

```bash
docker run -d \
  --name goose-server \
  --restart unless-stopped \
  -p 8443:8443 \
  -v $(pwd)/server_config.json:/app/server_config.json:ro \
  ghcr.io/kianmhz/gooserelayvpn-server:latest
```

**Docker Compose (recommended for container setup):**

```bash
cp server_config.example.json server_config.json
nano server_config.json
docker compose up -d
```

The repo includes [`docker-compose.yml`](docker-compose.yml). By default it uses `ghcr.io/kianmhz/gooserelayvpn-server:latest`, and you can override it with:

```bash
GOOSE_SERVER_IMAGE=ghcr.io/kianmhz/gooserelayvpn-server:vX.Y.Z docker compose up -d
```

Verify from your own computer:

```bash
curl http://YOUR.VPS.IP:8443/healthz
```

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
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/root
StateDirectory=goose-relay
ExecStart=/root/goose-server -config /root/server_config.json
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
LimitNOFILE=1048576
OOMScoreAdjust=-500
Nice=-10
Environment="GOGC=200"
Environment="GOMEMLIMIT=400MiB"
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes

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

**Linux/macOS:**
```bash
./goose-client -config client_config.json
```

**Windows (cmd.exe or PowerShell):**
```cmd
.\goose-client.exe -config client_config.json
```

Use the backslash form (`.\...`) on Windows. `cmd.exe` does not understand the Unix-style `./goose-client.exe` form.

You should see output like this:

```
CLIENT  INFO    GooseRelayVPN client starting
CLIENT  INFO    SOCKS5 proxy: socks5://127.0.0.1:1080
CLIENT  INFO    pre-flight OK: at least one relay endpoint is healthy, AES key matches end-to-end
CLIENT  INFO    ready: local SOCKS5 is listening on 127.0.0.1:1080
```

The **pre-flight check** runs automatically at startup and verifies every currently available relay endpoint, while skipping endpoints that are already quarantined by saved quota state. If some deployments are quota-exhausted, rate-limited, or misconfigured but at least one endpoint is healthy, the client starts and quarantines the bad endpoints so they do not poison browsing. Transient network backoff is intentionally not persisted. If all endpoints fail, the message tells you what went wrong.

Now set your browser to use SOCKS5 proxy `127.0.0.1:1080`:

- **Firefox:** Settings → Network Settings → Manual proxy → SOCKS5 host `127.0.0.1` port `1080`. Check **Proxy DNS when using SOCKS v5**.
- **Chrome/Edge:** Use an extension like FoxyProxy or SwitchyOmega.
- **System-wide on macOS/Linux:** Set SOCKS5 in network settings.

---

## macOS Setup

The macOS archive contains the same `goose-client` program name, but you must download the Darwin archive for your Mac. Downloaded binaries may also have Gatekeeper's quarantine flag. Pick the right archive: **Apple Silicon (M1/M2/M3/M4)** → `darwin-arm64`; **Intel Mac** → `darwin-amd64`.

**1. Download and extract:**
```bash
cd ~/Downloads
tar -xzf GooseRelayVPN-client-vX.Y.Z-darwin-arm64.tar.gz
cd GooseRelayVPN-client-vX.Y.Z-darwin-arm64/
```

**2. Clear the Gatekeeper quarantine flag:**
```bash
xattr -d com.apple.quarantine goose-client 2>/dev/null || true
chmod +x goose-client
```

**3. Create your config:**
```bash
cp client_config.example.json client_config.json
open -e client_config.json
```
Fill in your `script_keys` and `tunnel_key`, save, and close.

**4. Run the client:**
```bash
./goose-client -config client_config.json
```

If you get `cannot execute binary file: Exec format error`, you downloaded the wrong architecture.

---

## Android Setup (Termux)

The Android client runs inside [Termux](https://termux.dev) — there is no APK. Follow these steps:

**1. Install and set up Termux:**
```bash
apt update && apt upgrade -y
pkg install wget tar -y
```

**2. Download and extract the client:**
```bash
VERSION=vX.Y.Z
wget https://github.com/Kianmhz/GooseRelayVPN/releases/download/$VERSION/GooseRelayVPN-client-$VERSION-android-arm64.tar.gz
tar -xzvf GooseRelayVPN-client-$VERSION-android-arm64.tar.gz
cd GooseRelayVPN-client-$VERSION-android-arm64/
chmod +x goose-client
```

Replace `vX.Y.Z` with the latest version from the Releases page.

**3. Create your config:**
```bash
cp client_config.example.json client_config.json
nano client_config.json
```
Fill in your `script_keys` and `tunnel_key`, then save with Ctrl+X.

**4. Run the client:**
```bash
./goose-client -config client_config.json
```

When you see `ready: local SOCKS5 is listening on 127.0.0.1:1080` it's working.

**5. Connect your apps:**

Use a SOCKS5-aware app to route traffic through `127.0.0.1:1080`. [NekoBox](https://github.com/MatsuriDayo/NekoBoxForAndroid) and [v2rayNG](https://github.com/2dust/v2rayNG) both work well:
- Add a SOCKS5 proxy pointing to `127.0.0.1:1080`
- In **per-app settings**, enable the proxy for the apps you want and **exclude Termux** from the VPN so the tunnel itself stays connected

---

## LAN Sharing (Optional)

By default the client listens on `127.0.0.1:1080` so only your computer can use it. To share with other devices on your local network, set `socks_host` to `0.0.0.0` in `client_config.json` and restart. If you do this, set both `socks_user` and `socks_pass`; otherwise anyone on that LAN can use your tunnel.

> ⚠️ **Security note:** Anyone on your LAN can then proxy through your tunnel and consume your Apps Script quota. Only do this on trusted networks.

---

## Increase capacity with multiple deployments (recommended)

Google documents Apps Script URL Fetch quota as a per-user/account quota, about **20,000 calls/day** for consumer accounts, and daily quotas reset 24 hours after first use, not at a guaranteed wall-clock time. Treat deployments under the same Google account as sharing one quota pool; do not assume each deployment or project gets a separate pool. The client polls about once per second when idle, so a single deployment can sustain steady use, but heavy days hit the cap. Real-time apps like **Telegram or X can drain the quota within a few hours** due to constant polling. To go beyond that, deploy `Code.gs` across **different Google accounts** and put all the Deployment IDs into `script_keys`.

> ⚠️ **Label every deployment with the Google account it lives under.** Active POST workers scale by deployment count, while idle long-polls are capped by throttle bucket. Two labeled deployments under the same Google account share one idle bucket; unlabeled deployments are treated as separate buckets because the client cannot prove they share an account.

```json
{
  "script_keys": [
    {"id": "FIRST_DEPLOYMENT_ID",  "account": "acct-a"},
    {"id": "SECOND_DEPLOYMENT_ID", "account": "acct-a"},
    {"id": "THIRD_DEPLOYMENT_ID",  "account": "acct-b"},
    {"id": "FOURTH_DEPLOYMENT_ID", "account": "acct-b"}
  ]
}
```

The example above is 4 deployments across 2 accounts: active POST workers use all 4 deployments, while idle long-polls use 2 account buckets. That gives more active throughput and twice the daily quota of a single account without overloading either account with standing polls.

If you leave the labels off (`["ID1", "ID2", ...]` plain strings), each deployment gets its own implicit bucket for legacy compatibility. If several deployments are actually under the same Google account, give them the same `account` label so idle long-polls do not overload that one account.

What the client does for you automatically:

- **Round-robin** across all configured deployments within active buckets.
- **Health-aware blacklist** — if one starts failing, the client backs off from it (3 s, 6 s, 12 s, … up to ~48 s) and keeps using the others.
- **Same-poll failover** — if a poll fails on one deployment, the same payload is retried on another within the same poll cycle, so no traffic is lost during transient quota or 5xx events.
- **Per-account stats** — the periodic `[stats]` line aggregates request counts per account label so you can see how each Google account's daily quota is being spent.

> 💡 All deployments must use **the same `tunnel_key`** because they all forward to the same VPS, which only has one AES key. You don't need to change anything on the VPS when you add more deployments.

> 💡 You can paste either just the Deployment ID (the part between `/s/` and `/exec`) or the full `/exec` URL — the client extracts the ID either way.

> 💡 **A practical upper bound is 2–3 accounts.** Adding more deployments under accounts you already have just spreads quota and rarely improves throughput; what helps is *another distinct account*.

---

## Direct Stream Mode

For the lowest latency direct-to-VPS path, add `direct_stream_urls` to `client_config.json` and set `transport_mode` to `auto`:

```json
{
  "transport_mode": "auto",
  "direct_stream_urls": ["ws://YOUR.VPS.IP:8443/stream"],
  "script_keys": ["APPS_SCRIPT_FALLBACK_DEPLOYMENT_ID"]
}
```

Use `wss://` only when you put `goose-server` behind a TLS reverse proxy; the bundled server itself listens with plain `ws://`. `auto` tries the WebSocket `/stream` endpoint first if `direct_stream_urls` is configured. For POST fallback, it uses **one** POST transport: `relay_urls` if configured, otherwise Apps Script `script_keys`. In the current version, setting `relay_urls` means Apps Script is not also used as a second POST fallback. Use `direct_stream`, `direct_post`, or `apps_script` to force one path. Apps Script cannot carry WebSockets; it remains the safest compatibility path when direct VPS access is blocked.

Optional stream knobs are `stream_connect_timeout_ms` (default `5000`), `stream_ping_interval_ms` (default `20000`), and `stream_reconnect_backoff_ms` (default `1000`). `auto_tune` can be set to `true` to let the client adjust `poll_idle_sleep_ms` inside fixed caps using observed TTFB; it never changes crypto, wire compatibility, connect timeouts, or payload limits.

---

## Configuration

### Client (`client_config.json`)

| Field | Default | What it does |
|---|---|---|
| `socks_host` | `127.0.0.1` | Host/IP for the local SOCKS5 listener. Set to `0.0.0.0` for LAN sharing, but also set `socks_user` and `socks_pass`. |
| `socks_port` | `1080` | Port for the local SOCKS5 listener. |
| `google_host` | `216.239.38.120` | Google edge IP/host to dial (port is fixed to `443`). |
| `sni` | `["www.google.com", "mail.google.com", "accounts.google.com"]` | SNI presented during the TLS handshake. Accepts a single string or an array. Each SNI host gets its own connection pool and TLS sessions. This can help in networks that treat Google front names differently, but it is empirical, not a Google-documented throttle guarantee. |
| `fronting_http_version` | `auto` | Domain-fronted HTTP version. `auto` keeps the normal HTTP/2-first behavior; `h1` forces independent HTTP/1.1 connections for testing lossy mobile networks; `h2` forces HTTP/2. |
| `transport_mode` | `apps_script` | Default is the fronted Apps Script path because direct VPS access is often blocked. Set `auto` only when you intentionally configured `direct_stream_urls` or `relay_urls` and want the client to try that direct path. `direct_post` and `direct_stream` force one direct route. |
| `direct_stream_urls` | `[]` | Optional direct WebSocket endpoints such as `ws://YOUR.VPS.IP:8443/stream`. Used only when `transport_mode` is `auto` or `direct_stream`. Use `wss://` only behind your own TLS reverse proxy. Leave empty if direct VPS access is blocked or unstable. |
| `relay_urls` | `[]` | Optional direct POST `/tunnel` endpoints such as `http://YOUR.VPS.IP:8443/tunnel`. Used only when `transport_mode` is `auto` or `direct_post`; otherwise leave empty for normal Apps Script/fronting use. |
| `downstream_replay_mode` | `auto` | Downstream lost-response recovery for Apps Script/direct POST. `auto` sends ACKs/replays only when the server advertises `downstream_replay_v1`; use `off` to preserve old behavior. Direct stream is not changed by this setting. |
| `fresh_start_reset` | `true` | On startup, ask a compatible VPS to close stale sessions from the previous run of this same client instance. This makes Ctrl+C then start behave like a fresh tunnel without restarting the VPS process. It cannot reset Google quota. |
| `client_instance_id` | *(auto)* | Stable label for this device/client. Leave empty and the client creates `.goose-client-instance` beside the config. Do not reuse the same ID on two devices that run at the same time, because startup reset is scoped to this ID. |
| `client_instance_id_file` | `.goose-client-instance` | Optional file path for the generated client instance ID. Relative paths are resolved beside `client_config.json`. |
| `quota_state_path` | `.goose-quota-state.json` | Persists daily quota quarantines so restarts do not waste time retrying accounts already known to be quota-dead today. Set to `""` to disable persistence. Transient network blacklists are not persisted. |
| `script_keys` | — | Array of Apps Script deployments. Each entry can be a bare Deployment ID string or an object `{ "id": "...", "account": "..." }` labeling the Google account it's deployed under. **The `account` label is load-bearing for idle caps and quota interpretation**: deployments with the same label share one idle-poll bucket; unlabeled deployments are treated as separate buckets for legacy compatibility. If several deployments are under one Google account, label them the same to avoid excessive standing polls on that account. See [Increase capacity with multiple deployments](#increase-capacity-with-multiple-deployments). |
| `tunnel_key` | — | 64-char hex AES-256 key. Must match the server byte-for-byte. |
| `socks_user` | *(optional)* | SOCKS5 username (RFC 1929). When set, clients must authenticate or the connection is rejected. Must be paired with `socks_pass` — set both or neither. |
| `socks_pass` | *(optional)* | SOCKS5 password paired with `socks_user`. |
| `max_local_sessions` | `0` | Optional cap on concurrent local SOCKS sessions accepted by the SOCKS listener. `0` means the listener itself does not impose an extra cap, but the carrier still keeps its built-in storm guard (1024 active sessions and 80 new sessions/sec) to protect memory. Set a positive value such as `512` if you want a lower user-visible cap. |
| `coalesce_step_ms` | `0` (off) | Adaptive uplink coalescing. Set it to a positive number to make the first kick of a burst of TX operations wait a little for more operations; each new operation resets the timer. This trades a bit of latency for fewer Apps Script calls. A good starting range is 20-40 ms. Set it to `0` to turn coalescing off. The internal safety cap is derived automatically from this value. |
| `idle_slots_per_bucket` | `1` | Download-throughput tuning. The carrier holds this many concurrent idle long-polls open per account bucket to receive downstream pushes. Default `1` is the safe baseline established by issue #56's fix. Raise to `2` if each Google account has 2+ deployments — this may increase download throughput; leave at `1` if each account has only one deployment (raising it would put 2 simultaneous polls on a single deployment URL, which is more likely to trip Apps Script's per-account concurrency cap). In a single-bucket pure-download burst the client may temporarily allow 2 idle polls for responsiveness even when this is `1`. Max `3`; values above are rejected. |
| `idle_poll_mode` | `always` | Apps Script quota saver. `always` preserves the fastest idle behavior, `adaptive` reduces idle polls after 30s with zero active sessions and stops them after 5 minutes, and `off` disables idle polls whenever no sessions exist. Any new SOCKS session wakes workers immediately. |
| `idle_poll_max_buckets` | `2` | Maximum account buckets used by idle polls while there are zero active sessions. This prevents a 4-account setup from spending all accounts' quota just because the client is open. Active sessions can still use all buckets. |
| `workers_per_endpoint` | `3` | Active POST poll workers per relay endpoint/deployment. Higher values can reduce latency on fast, stable routes but burn quota faster and increase Apps Script simultaneous-execution pressure. |
| `tx_slots_per_bucket` | `3` | Maximum concurrent active POSTs per Google account bucket. This prevents all workers from piling onto one remaining healthy account after other accounts hit quota. Try `1-2` for fragile accounts; raise above `3` only after logs prove the account handles it. |
| `tx_buffer_budget_bytes` | `67108864` | Global queued upload buffer budget across all local sessions. The default 64 MiB protects Android/Termux from many parallel tabs filling memory while preserving the existing 8 MiB per-session ceiling. |
| `save_terminal_log` | `false` | Debug helper for field tests. When `true`, logs still print in the terminal and are also saved to a `.log` file. Terminal logs are **not redacted** and may include destination domains/IPs plus full direct URLs or tokens, so review them before sharing. |
| `terminal_log_file` | *(empty)* | Optional filename/prefix for `save_terminal_log`. Empty auto-creates `logs/goose-client-YYYYMMDD-HHMMSS.log` beside the client binary; a custom path still creates a fresh timestamped file every run. |

### Server (`server_config.json`)

| Field | Default | What it does |
|---|---|---|
| `server_host` | `0.0.0.0` | Host/IP where the exit server binds. |
| `server_port` | `8443` | Port where the exit server listens. Must be reachable from Google's network. |
| `tunnel_key` | — | 64-char hex AES-256 key. Must match the client. |
| `upstream_proxy` | *(optional)* | Route all outbound connections through a SOCKS5 proxy. Useful when your VPS datacenter IP is blocked by certain sites. Set `socks5://127.0.0.1:40000` for local Cloudflare WARP, or `socks5://user:pass@host:port` for a proxy that requires auth. DNS is resolved by the proxy, so target sites see the proxy IP instead of your VPS IP. Leave empty or omit to dial directly. |
| `auto_tune` | `false` | When `true`, the server adjusts only `active_drain_window_ms` and the coalesce windows inside fixed safety caps based on downstream queue wait. It does not change `long_poll_window_ms`, dial timeouts, session limits, or body-size limits. |
| `long_poll_window_ms` | `6000` | How long the VPS can hold an idle poll open waiting for downstream bytes. The example uses `8000` with `idle_poll_mode: "adaptive"` to reduce idle Apps Script invocations while active data still returns immediately. |
| `upstream_dial_timeout_ms` | `8000` | Exit-side TCP dial timeout for new upstream connections. Set `15000` if your upstream/proxy path is unusually slow; lower values fail dead CDN edges faster. |
| `debug_timing` | `false` | When `true`, logs per-session DNS and TCP dial latency so you can pinpoint where time is going. |
| `save_terminal_log` | `false` | Debug helper for field tests. When `true`, logs still print in the terminal/systemd journal and are also saved to a `.log` file. Terminal logs are **not redacted** and may include destination domains/IPs plus full direct URLs or tokens, so review them before sharing. |
| `terminal_log_file` | *(empty)* | Optional filename/prefix for `save_terminal_log`. Empty auto-creates `logs/goose-server-YYYYMMDD-HHMMSS.log` beside the server binary; a custom path still creates a fresh timestamped file every run. |
| `max_sessions` | `4096` | Maximum concurrent server-side tunnel sessions. This protects VPS RAM/file descriptors during connection storms; excess SYNs are reset quickly so apps can retry instead of hanging. |
| `max_drain_frames_per_session` | `8` | Server-only download fairness knob. It limits how many `256 KiB` downstream frames one hot TCP session can take from a single server response. Use `8` for mixed browsing/video, `16` as the first bulk-download test, and `24` or `32` only for aggressive single-download testing where larger Apps Script responses and longer waits for other sessions are acceptable. |
| `max_request_body_bytes` | `12582912` | VPS HTTP request-body cap. The default fits the 8 MiB client upload batch after Apps Script/base64 expansion while keeping unauthenticated request memory bounded. Raise both client and server caps only if you intentionally increase upload batch size. |
| `max_response_bytes_pre_encode` | `6291456` | Server-to-client response batch cap before encryption/base64 after the startup ramp. `2097152` is safest on weak mobile links, `4194304` is conservative, and `6291456` is the balanced download default. With replay enabled, keep this at or below `8388608`. Raising toward `23068672` is expert-only for stable links with replay disabled. |
| `initial_response_cap_enabled` | `true` | Enables the first-response ramp cap. Set `false` to ignore `initial_response_bytes_pre_encode` without editing the byte number, useful for maximum bulk-download testing. |
| `initial_response_bytes_pre_encode` | `524288` | First downstream response cap per session when `initial_response_cap_enabled` is `true`. Keeps the first bytes of a page/video from being stuck behind a large download response. |
| `second_response_cap_enabled` | `true` | Enables the second-response ramp cap. Set `false` to ignore `second_response_bytes_pre_encode` without editing the byte number. |
| `second_response_bytes_pre_encode` | `1048576` | Second downstream response cap per session when `second_response_cap_enabled` is `true`. `1048576` is smoother for Apps Script/mobile video starts; try `2097152` only if downloads are stable and quota is healthy. Later responses use `max_response_bytes_pre_encode`. |
| `downstream_replay_enabled` | `false if omitted, true in examples` | Bounded replay buffer for downstream Apps Script/direct POST responses. Use with client `downstream_replay_mode: "auto"`. Per-session replay is capped at 8 MiB, per-client replay at 64 MiB, and stale replay state expires after 5 minutes. |

---

## Updating

Configs are forward-compatible: new fields in `client_config.json` / `server_config.json` default sensibly, and old fields keep working. You generally do not need to start over.

One important transport note for older direct-mode configs: if your old client config omitted `transport_mode` but relied on `relay_urls` or `direct_stream_urls`, add `"transport_mode": "auto"`, `"direct_post"`, or `"direct_stream"` explicitly. The default is now `"apps_script"` so the normal censorship-resistant Apps Script path stays predictable.

### Server

1. Stop the running server (`sudo systemctl stop goose-relay` on Linux systemd, or stop your tmux/manual process).
2. Replace `goose-server` / `goose-server.exe` with the new binary.
3. Keep `server_config.json` as-is unless a release note explicitly asks you to add a field.
4. Restart the server.

### Client

1. Stop the running `goose-client`.
2. Replace `goose-client` / `goose-client.exe` with the new binary.
3. Keep your existing `client_config.json`.
4. On macOS only, clear the quarantine flag again:
   ```bash
   xattr -d com.apple.quarantine goose-client 2>/dev/null || true
   chmod +x goose-client
   ```
5. Start the client again.

If `Code.gs` did not change, you do not need to redeploy Apps Script.

### Apps Script forwarder

If you change `Code.gs` — for example to point at a new VPS IP — saving alone does nothing; the live `/exec` URL serves a deployed version. You can either create a **new deployment** and update `script_keys`, or create a new version and edit the existing web-app deployment to use it if you want to keep the same Deployment ID.

The current `Code.gs` exposes forwarder/protocol metadata via `doGet` for the client's pre-flight check. It can also expose an approximate per-deployment web-app request count when `ENABLE_INVOCATION_COUNTING` is set to `true`; counting is disabled by default because writing Apps Script properties on every tunnel request adds latency. Treat that count as a local pressure signal, not an exact Google URL Fetch quota meter. When disabled, `doGet` reports `counting_enabled:false` so the client does not mistake `count:null` for a real counter.

---

## Architecture

```
┌─────────┐   ┌──────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────┐
│ Browser │──►│ goose-client │──►│ Google edge  │──►│ Apps Script │──►│  Your    │──► Internet
│  / App  │◄──│  (SOCKS5)    │◄──│ TLS, fronted │◄──│  doPost()   │◄──│  VPS     │◄──
└─────────┘   └──────────────┘   └──────────────┘   └─────────────┘   └──────────┘
              AES-256-GCM         Google SNI         dumb forwarder    decrypt +
              session multiplex   Host=script.…      no plaintext      net.Dial
```

Key invariants:

- **Authentication = AES-GCM tag.** No shared password, no certificates. Frames that fail `Open()` are dropped silently.
- **Apps Script never sees plaintext.** The script is a small forwarder; the AES key lives only on your machine and the VPS.
- **DNS travels through the tunnel.** The SOCKS5 server uses a no-op resolver; use `socks5h://` so DNS is resolved at the exit, not locally.
- **Long-poll, full-duplex.** The VPS holds each request open for the configured `long_poll_window_ms` (default 6s; the example config uses 8s) waiting for downstream bytes; the client scales active POST workers by deployment count, while idle long-polls are capped by account/URL bucket. Labeled deployments under the same account share one idle bucket; unlabeled deployments are treated as separate buckets for legacy compatibility. The bucket model exists because Apps Script's simultaneous-execution and short-time invocation limits are per account. Response coalescing is configurable and defaults to 0 ms in latency mode.
- **Downstream replay is opt-in.** When enabled on both client and server, POST transports piggyback small ACK control frames and the VPS keeps a bounded copy of sent-but-unacknowledged downstream frames. If a mobile/Google HTTP response is lost, a later poll can replay those frames before fresh bytes. This is for reliability, not speed; direct WebSocket stream keeps the normal stream behavior.
- **Health-aware multi-deployment.** When `script_keys` lists more than one deployment, the client picks endpoints by health, RTT, and quota pressure. TX batches retry across every configured endpoint before giving up, so one exhausted deployment cannot discard data while another deployment is still healthy.

### Wire format

- **Frame** (plaintext, inside the sealed batch): `session_id (16) || seq (u64 BE) || flags (u8) || target_len (u8) || target || payload_len (u32 BE) || payload`
- **Batch seal** (AES-GCM): the entire batch is sealed once — `nonce (12 bytes) || AES-GCM(flags (u8) || client_id (16) || u16 frame_count || [u32 frame_len || frame_bytes] …)` — one nonce and auth-tag per HTTP body, not per frame.
- **HTTP body**: Apps Script text mode uses `base64(nonce || ciphertext+tag)` so it survives `ContentService` text round-trips. Direct POST and direct stream can negotiate/send raw binary `nonce || ciphertext+tag` bodies because they do not pass through Apps Script.

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
├── bench/
│   ├── harness/main.go             # E2E benchmark: real binaries, loopback sink
│   ├── sink/main.go                # TCP sink (echo / sized / source / quick modes)
│   ├── diff/main.go                # JSON result comparator with noise-floor logic
│   ├── baselines/                  # Committed baseline JSON files
│   └── bench.sh                   # Build + run + compare orchestrator
├── apps_script/
│   └── Code.gs                     # Apps Script forwarder
├── scripts/
│   └── goose-relay.service         # systemd unit template
├── client_config.example.json
└── server_config.example.json
```

---

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `cannot execute binary file: Exec format error` when running `goose-server` or `goose-client` | You downloaded the wrong archive for your OS/architecture. The folder name tells you what you got — e.g. `…-darwin-amd64` is a **macOS** binary and won't run on Linux. Re-download the matching archive (Linux VPS → `linux-amd64`; Apple Silicon Mac → `darwin-arm64`; Termux → `android-arm64`). |
| Pre-flight fails: `cannot reach Apps Script` | Your internet connection can't reach Google. Check `google_host` — try another current Google-owned edge IP and let the startup probe keep only working SNI hosts. |
| Pre-flight fails: `HTTP 204 — key mismatch` | The `tunnel_key` in `client_config.json` doesn't match the one in `server_config.json` on the VPS. They must be byte-identical. |
| Pre-flight fails: `Apps Script cannot reach your VPS` | Port 8443 on your VPS is not reachable. Run `sudo ufw allow 8443/tcp` on the VPS and check your cloud provider's firewall rules. |
| Log says `relay returned non-batch payload` | Apps Script returned HTML/JSON/text instead of an encrypted batch. Common causes: (1) the deployment in `script_keys` is not live, or **Who has access** is not set to `Anyone` — deploy a current version and make sure the Deployment ID matches your config; (2) the deployment was added to an existing Apps Script project alongside other files — create a **new** project with only `Code.gs` in it, then deploy from there; (3) an old deployment is still serving a pre-v2 `Code.gs` that returned upstream error text with HTTP 200; (4) you have multiple deployments under the same Google account and are hitting that account's simultaneous-execution or short-time invocation limits — label `script_keys` entries with their `account` so the client throttles per account (see [Increase capacity with multiple deployments](#increase-capacity-with-multiple-deployments)). |
| Log says `relay returned HTTP 404 via …` | The Deployment ID in your config doesn't match a live `/exec`. Re-deploy and update the config. |
| Log says `relay returned HTTP 500 via …` | Apps Script/Google returned a wrapper-level error, or current `Code.gs` threw because every `RELAY_URLS` target failed. Check the response body in the logs: quota text points to Apps Script/UrlFetch quota, while upstream fetch/status text points to VPS reachability, `/tunnel`, tunnel key, or upstream proxy trouble. |
| Log says `relay request failed via …: timeout` | Fronted connection to Google is failing. Try another current Google-owned edge IP in `google_host`; Google IP ranges change, so rely on the startup probe rather than assuming every `216.239.x.120` address works forever. |
| Browser hangs on every request | Make sure your browser extension uses SOCKS5 with **DNS through proxy** enabled (not plain SOCKS5). In Firefox, check **Proxy DNS when using SOCKS v5**. |
| `[exit] dial X: ... timeout` on the VPS server logs | The target host blocks datacenter IPs, or your VPS has no outbound connectivity for that port. |
| Cloudflare-protected sites show captchas | Expected. Your VPS's IP is on a datacenter ASN, which Cloudflare's bot scoring often flags. Not a tunnel bug. |
| YouTube buffers a lot at 1080p | Expected. The tunnel adds ~300-800ms per round trip due to Apps Script dispatch overhead. 480p is comfortable. Deploying multiple `script_keys` (see above) helps with sustained throughput. |
| One deployment hits quota mid-session | If `script_keys` has more than one entry, the client automatically blacklists the failing one for a few seconds and keeps going on the others. With only one account, browsing stops until Google's account quota window resets. |
| Mismatched AES keys | Symptom: client logs no errors but no traffic flows; VPS logs no `dial ...` lines. Confirm `tunnel_key` is byte-identical in both configs. |

To collect a shareable support bundle without exposing tunnel secrets, run:

```bash
./goose-client -config client_config.json -dump-diag
```

The generated `goose-diagnostics-*.zip` includes runtime, goroutine, heap, structured summary, and redacted client-config data. Use `-diag-output path/to/file.zip` if you want a specific output path. The server has the same support path via `./goose-server -config server_config.json -dump-diag`.

For deeper local profiling during a test run, start either binary with `-debug-pprof 127.0.0.1:6060` and inspect it with `go tool pprof`. The pprof listener is intentionally localhost-only because it exposes runtime internals without authentication; binds such as `0.0.0.0:6060` are refused. Use `-stats-json` when you want periodic stats as machine-readable JSON log lines for later analysis. The same continuous diagnostics can also be enabled from config with `debug_pprof_addr` and `stats_json`; set `write_startup_diagnostics` to write one redacted zip on startup without changing your normal launch command. Relative diagnostics/log paths are created beside the running binary, so a server binary in `/root/23goosecodex` writes to `/root/23goosecodex/diagnostics/` and `/root/23goosecodex/logs/`. Each restart creates a fresh timestamped diagnostics zip and terminal log file. If a service manager runs the binary from a read-only install directory, configure absolute writable paths instead. In Docker, use `/app/diagnostics` through the mounted `./diagnostics:/app/diagnostics` volume.

To summarize long client/server logs after a real-world test run:

```bash
go run ./cmd/analyze client.log server.log
go run ./cmd/analyze --follow logs/goose-client-*.log logs/goose-server-*.log
```

The analyzer looks for quota exhaustion, local network outages, bad deployment/key/protocol responses, slow Google/fronting polls, slow upstream/WARP first reads, high queue wait, receive aborts such as `rx_reorder_overflow`, and endpoint failure-reason counters.
With `--follow`, it tails appended log data and prints a fresh report only when
new actionable signals appear, which is useful during field tests without
copying the terminal by hand.

For Android/mobile reliability testing, use the checklist and mobile-safe
profile in [`docs/TESTING_REAL_WORLD.md`](docs/TESTING_REAL_WORLD.md). It
spells out the exact logs, diagnostics zips, replay settings, and response-size
values to capture before tuning further.

---

## Security Tips

- **Never share `client_config.json` or `server_config.json`** — the AES key is in there and a leaked key means anyone can tunnel through your VPS.
- **Generate one fresh key with `openssl rand -hex 32` for each VPS/client group.** All Apps Script deployments that forward to that same VPS must use the same key. Do not reuse keys across unrelated hosts.
- **AES-GCM is the only authentication.** There's no password, no rate-limiting, no per-user accounting. Treat the key like a server-admin password.
- **Apps Script logs executions in Google's dashboard** (count and duration only — Apps Script never sees plaintext). The optional `ENABLE_INVOCATION_COUNTING` counter is off by default for latency.
- **Keep `socks_host` on the client at `127.0.0.1`** unless you specifically want LAN sharing. If you bind to `0.0.0.0`, set `socks_user` and `socks_pass`.
- **Apps Script URL Fetch quota is per user/account**: about 20,000 calls/day for consumer accounts. Treat deployments under the same Google account as sharing one pool.

---

## Contributing

Pull requests are welcome. For any change that touches the carrier loop, session layer, or poll behavior, please include benchmark results so reviewers can evaluate the performance impact.

The `bench/` directory contains an end-to-end harness that spins up real `goose-client` and `goose-server` binaries against a loopback TCP sink and measures throughput, TTFB, session rate, and idle CPU.

```bash
# Build the binaries and run the full benchmark suite
bash bench/bench.sh

# Guard the frame/batch hot path against allocation or throughput regressions
go test -bench 'Benchmark(Frame|EncodeBatch|DecodeBatch|SealOpen)' -benchmem ./internal/frame

# Compare direct POST and direct WebSocket stream latency
bash bench/bench.sh --smoke --scenario ttfb_p50_p95 --transport direct_post
bash bench/bench.sh --smoke --scenario ttfb_p50_p95 --transport direct_stream

# Exercise retry/replay behavior under synthetic mobile-like POST impairment
bash bench/bench.sh --smoke --scenario ttfb_p50_p95 --impairment mobile
```

The harness compares your working tree against the committed baseline in `bench/baselines/` and prints a side-by-side table. Regressions above the noise floor fail the script with exit code 1. Include the output in your PR description.

To record a new baseline from a specific git ref:

```bash
bash bench/bench.sh --update <ref>   # e.g. --update v1.6.0 or --update HEAD
```

---

## Special Thanks

Special thanks to [@abolix](https://github.com/abolix) for making this project possible.

## License

MIT
