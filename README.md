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
  -> Zstd-compressed + AES-256-GCM frame batches
  -> HTTPS to a Google edge IP   (SNI=www.google.com, Host=script.google.com)
  -> Apps Script doPost()        (dumb forwarder, never sees plaintext)
  -> Your VPS :8443/tunnel       (decrypts, demuxes by session_id, dials target)
  <- Same path in reverse via long-polling
```

Your application sends TCP bytes through the SOCKS5 listener on your computer. The client groups them into batches of frames, **Zstandard-compresses** each batch (for compressible traffic such as plain HTTP or JSON APIs this reduces the body size by up to 65%, keeping you further from Apps Script's daily quota limits), then seals the whole batch under a single **AES-256-GCM** envelope and POSTs it over a domain-fronted HTTPS connection to your Apps Script web app. The Apps Script is a ~30-line script that forwards the body verbatim to your VPS — it never decrypts and the AES key never touches Google. Your VPS decrypts, dials the real target, and pumps bytes back along the same path. The filter sees only TLS to Google.

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

> 💡 **If the Releases page doesn't open**, you can download directly using these links (replace `vX.Y.Z` with the latest version):
> - **Client — Windows:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-windows-amd64.zip`
> - **Client — macOS (Apple Silicon):** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-darwin-arm64.tar.gz`
> - **Client — macOS (Intel):** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-darwin-amd64.tar.gz`
> - **Client — Linux:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-linux-amd64.tar.gz`
> - **Client — Android/Termux:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-client-vX.Y.Z-android-arm64.tar.gz`
> - **Server — Linux:** `https://github.com/Kianmhz/GooseRelayVPN/releases/download/vX.Y.Z/GooseRelayVPN-server-vX.Y.Z-linux-amd64.tar.gz`

**Option B — Build from source (Go 1.22+) — not recommended, may be unstable:**

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
   const RELAY_URLS = ['http://YOUR.VPS.IP:8443/tunnel'];
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

You should get JSON like `{ "ok": true, "version": "vX.Y.Z", "protocol": 1 }` with HTTP 200. If `curl` times out or refuses, also check your **cloud provider's firewall** (called "Security Groups" on AWS/Hetzner, "Firewall Rules" on DigitalOcean/Vultr, etc.) and add an inbound rule for TCP port 8443.

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
ExecStart=/root/goose-server -config /root/server_config.json
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
LimitNOFILE=1048576
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

## Android Setup (Termux)

The Android client runs inside [Termux](https://termux.dev) — there is no APK. Follow these steps:

**1. Install and set up Termux:**
```bash
apt update && apt upgrade -y
pkg install wget tar -y
```

**2. Download and extract the client:**
```bash
wget https://github.com/Kianmhz/GooseRelayVPN/releases/latest/download/GooseRelayVPN-client-v1.6.0-android-arm64.tar.gz
tar -xzvf GooseRelayVPN-client-v1.6.0-android-arm64.tar.gz
cd GooseRelayVPN-client-v1.6.0-android-arm64/
chmod +x goose-client
```

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

By default the client listens on `127.0.0.1:1080` so only your computer can use it. To share with other devices on your local network, set `socks_host` to `0.0.0.0` in `client_config.json` and restart.

> ⚠️ **Security note:** Anyone on your LAN can then proxy through your tunnel and consume your Apps Script quota. Only do this on trusted networks.

---

## Increase capacity with multiple deployments (recommended)

The **~20,000 calls/day quota applies per Google account**, not per deployment or project — all deployments under the same account share one quota pool. The client polls about once per second when idle, so a single deployment can sustain steady use, but heavy days hit the cap. Real-time apps like **Telegram or X can drain the quota within a few hours** due to constant polling. To go beyond that, deploy `Code.gs` across **different Google accounts** and put all the Deployment IDs into `script_keys`.

> ⚠️ **Label every deployment with the Google account it lives under.** The client scales its concurrency (4 poll workers per "bucket") by **distinct account labels**, not by deployment count — because Apps Script's per-second concurrency cap is also per-account. Two deployments under the same account share one quota and one bucket; two deployments under different accounts give you two buckets.

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

The example above is 4 deployments across 2 accounts → **2 buckets → 8 poll workers, 2 standing long-polls** — twice the parallelism and twice the daily quota of a single account, without overloading either.

If you leave the labels off (`["ID1", "ID2", ...]` plain strings), all deployments collapse into one anonymous bucket — same workers and same idle slots as a single deployment. The client logs a `WARN` at startup so you don't miss it. Use plain strings only if all your deployments really are under one Google account; otherwise label them.

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

For the lowest latency direct-to-VPS path, add `direct_stream_urls` to `client_config.json` and keep `transport_mode` at `auto`:

```json
{
  "transport_mode": "auto",
  "direct_stream_urls": ["wss://YOUR.VPS.DOMAIN:8443/stream"],
  "script_keys": ["APPS_SCRIPT_FALLBACK_DEPLOYMENT_ID"]
}
```

`auto` tries the WebSocket `/stream` endpoint first, then direct binary POST via `relay_urls` if configured, then Apps Script. Use `direct_stream`, `direct_post`, or `apps_script` to force one path. Apps Script cannot carry WebSockets; it remains the compatibility fallback.

Optional stream knobs are `stream_connect_timeout_ms` (default `5000`), `stream_ping_interval_ms` (default `20000`), and `stream_reconnect_backoff_ms` (default `1000`). `auto_tune` can be set to `true` to let the client adjust `poll_idle_sleep_ms` inside fixed caps using observed TTFB; it never changes crypto, wire compatibility, connect timeouts, or payload limits.

---

## Configuration

### Client (`client_config.json`)

| Field | Default | What it does |
|---|---|---|
| `socks_host` | `127.0.0.1` | Host/IP for the local SOCKS5 listener. Set to `0.0.0.0` for LAN sharing. |
| `socks_port` | `1080` | Port for the local SOCKS5 listener. |
| `google_host` | `216.239.38.120` | Google edge IP/host to dial (port is fixed to `443`). |
| `sni` | `["www.google.com", "mail.google.com", "accounts.google.com"]` | SNI presented during the TLS handshake. Accepts a single string or an array. Each SNI host gets its own connection and throttle bucket, which can multiply available bandwidth in regions that rate-limit per domain name. |
| `script_keys` | — | Array of Apps Script deployments. Each entry can be a bare Deployment ID string or an object `{ "id": "...", "account": "..." }` labeling the Google account it's deployed under. **The `account` label is load-bearing**: the client groups deployments by account and runs 4 poll workers per *account bucket* (more if you raise `idle_slots_per_bucket`), matching Apps Script's per-account concurrency cap. Bare strings (or unlabeled objects) all collapse into one anonymous bucket — fine if every deployment is under one Google account, but if they're under multiple accounts, label them or you lose the parallelism. See [Increase capacity with multiple deployments](#increase-capacity-with-multiple-deployments). |
| `tunnel_key` | — | 64-char hex AES-256 key. Must match the server byte-for-byte. |
| `socks_user` | *(optional)* | SOCKS5 username (RFC 1929). When set, clients must authenticate or the connection is rejected. Must be paired with `socks_pass` — set both or neither. |
| `socks_pass` | *(optional)* | SOCKS5 password paired with `socks_user`. |
| `coalesce_step_ms` | `0` (off) | Adaptive uplink coalescing. Set it to a positive number to make the first kick of a burst of TX operations wait a little for more operations; each new operation resets the timer. This trades a bit of latency for fewer Apps Script calls. A good starting range is 20-40 ms. Set it to `0` to turn coalescing off. The internal safety cap is derived automatically from this value. |
| `idle_slots_per_bucket` | `1` | Download-throughput tuning. The carrier holds this many concurrent idle long-polls open per account bucket to receive downstream pushes. Default `1` is the safe baseline established by issue #56's fix. Raise to `2` if each Google account has 2+ deployments — this may increase download throughput; leave at `1` if each account has only one deployment (raising it would put 2 simultaneous polls on a single deployment URL, which is more likely to trip Apps Script's per-account concurrency cap). Max `3`; values above are rejected. |

### Server (`server_config.json`)

| Field | Default | What it does |
|---|---|---|
| `server_host` | `0.0.0.0` | Host/IP where the exit server binds. |
| `server_port` | `8443` | Port where the exit server listens. Must be reachable from Google's network. |
| `tunnel_key` | — | 64-char hex AES-256 key. Must match the client. |
| `upstream_proxy` | *(optional)* | Route all outbound connections through a local SOCKS5 proxy. Useful when your VPS datacenter IP is blocked by certain sites. Set to `socks5://127.0.0.1:40000` to use Cloudflare WARP (DNS is resolved by the proxy, so target sites see the Cloudflare IP instead of your VPS IP). Leave empty or omit to dial directly. |
| `auto_tune` | `false` | When `true`, the server adjusts only `active_drain_window_ms` and the coalesce windows inside fixed safety caps based on downstream queue wait. It does not change `long_poll_window_ms`, dial timeouts, session limits, or body-size limits. |
| `upstream_dial_timeout_ms` | `15000` | Exit-side TCP dial timeout for new upstream connections. Latency mode defaults this to `8000`; lower values fail dead CDN edges faster, higher values tolerate unusually slow networks. |
| `debug_timing` | `false` | When `true`, logs per-session DNS and TCP dial latency so you can pinpoint where time is going. |
| `max_request_body_bytes` | `12582912` | VPS HTTP request-body cap. Keep this above the client `max_request_bytes_pre_encode` because Apps Script text mode base64-expands request batches. |

---

## Updating the Apps Script forwarder

If you change `Code.gs` — for example to point at a new VPS IP — you must create a **new deployment** in the Apps Script editor (Deploy → **New deployment**, not just "Manage deployments"). Saving alone does nothing; the live `/exec` URL serves the published version. After redeploying, update `script_keys` in `client_config.json`.

The current `Code.gs` exposes forwarder/protocol metadata via `doGet` for the client's pre-flight check. It can also expose per-deployment invocation counts when `ENABLE_INVOCATION_COUNTING` is set to `true`; counting is disabled by default because writing Apps Script properties on every tunnel request adds latency.

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
- **Long-poll, full-duplex.** The VPS holds each request open for up to 8s waiting for downstream bytes; the client runs **4 concurrent poll workers per labeled `account` bucket** in `script_keys` (default; scales further with `idle_slots_per_bucket`) — so 1 account = 4 workers, 2 accounts = 8 workers, 3 accounts = 12 workers, regardless of how many deployment IDs each account has. The bucket model exists because Apps Script's per-second concurrency cap is per-account; scaling workers by deployment count instead caused users with multiple IDs under one account to see Apps Script HTML error pages mid-session. Downstream frames are coalesced in a small (~25 ms) window so streaming workloads send fewer, larger HTTP responses.
- **Health-aware multi-deployment.** When `script_keys` lists more than one deployment, the client picks endpoints by health, RTT, and quota pressure. TX batches retry across every configured endpoint before giving up, so one exhausted deployment cannot discard data while another deployment is still healthy.

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
├── bench/
│   ├── harness/main.go             # E2E benchmark: real binaries, loopback sink
│   ├── sink/main.go                # TCP sink (echo / sized / source / quick modes)
│   ├── diff/main.go                # JSON result comparator with noise-floor logic
│   ├── baselines/                  # Committed baseline JSON files
│   └── bench.sh                   # Build + run + compare orchestrator
├── apps_script/
│   └── Code.gs                     # ~30-line dumb forwarder
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
| Pre-flight fails: `cannot reach Apps Script` | Your internet connection can't reach Google. Check `google_host` — try a different IP from the 216.239.x.120 range. |
| Pre-flight fails: `HTTP 204 — key mismatch` | The `tunnel_key` in `client_config.json` doesn't match the one in `server_config.json` on the VPS. They must be byte-identical. |
| Pre-flight fails: `Apps Script cannot reach your VPS` | Port 8443 on your VPS is not reachable. Run `sudo ufw allow 8443/tcp` on the VPS and check your cloud provider's firewall rules. |
| Log says `relay returned non-batch payload` | Apps Script returned an HTML page instead of an encrypted batch. Three common causes: (1) the deployment in `script_keys` isn't live, or **Who has access** is not set to `Anyone` — re-deploy (Deploy → **New deployment**) and update `script_keys`; (2) the deployment was added to an existing Apps Script project alongside other files — create a **new** project with only `Code.gs` in it, then deploy from there; (3) you have multiple deployments under the same Google account and are hitting that account's per-second concurrency cap — label `script_keys` entries with their `account` so the client throttles per-account (see [Increase capacity with multiple deployments](#increase-capacity-with-multiple-deployments)). |
| Log says `relay returned HTTP 404 via …` | The Deployment ID in your config doesn't match a live `/exec`. Re-deploy and update the config. |
| Log says `relay returned HTTP 500 via …` | Apps Script can't reach a `RELAY_URLS` entry. Check the server address in `Code.gs`, confirm the VPS is up, and confirm inbound TCP/8443 is open. `curl http://your.vps.ip:8443/healthz` should return 200. |
| Log says `relay request failed via …: timeout` | Fronted connection to Google is failing. Try a different `google_host` — any 216.239.x.120 served by Google works. |
| Browser hangs on every request | Make sure your browser extension uses SOCKS5 with **DNS through proxy** enabled (not plain SOCKS5). In Firefox, check **Proxy DNS when using SOCKS v5**. |
| `[exit] dial X: ... timeout` on the VPS server logs | The target host blocks datacenter IPs, or your VPS has no outbound connectivity for that port. |
| Cloudflare-protected sites show captchas | Expected. Your VPS's IP is on a datacenter ASN, which Cloudflare's bot scoring often flags. Not a tunnel bug. |
| YouTube buffers a lot at 1080p | Expected. The tunnel adds ~300-800ms per round trip due to Apps Script dispatch overhead. 480p is comfortable. Deploying multiple `script_keys` (see above) helps with sustained throughput. |
| One deployment hits quota mid-session | If `script_keys` has more than one entry, the client automatically blacklists the failing one for a few seconds and keeps going on the others. With only one entry, browsing stops until the quota resets (~10:30 AM Iran time / midnight Pacific). |
| Mismatched AES keys | Symptom: client logs no errors but no traffic flows; VPS logs no `dial ...` lines. Confirm `tunnel_key` is byte-identical in both configs. |

To collect a shareable support bundle without exposing tunnel secrets, run:

```bash
./goose-client -config client_config.json -dump-diag
```

The generated `goose-diagnostics-*.zip` includes runtime, goroutine, heap, and redacted client-config data. Use `-diag-output path/to/file.zip` if you want a specific output path.

---

## Security Tips

- **Never share `client_config.json` or `server_config.json`** — the AES key is in there and a leaked key means anyone can tunnel through your VPS.
- **Generate a fresh key with `openssl rand -hex 32`** for every deployment. Don't reuse keys across hosts.
- **AES-GCM is the only authentication.** There's no password, no rate-limiting, no per-user accounting. Treat the key like a server-admin password.
- **Apps Script logs executions in Google's dashboard** (count and duration only — Apps Script never sees plaintext). The optional `ENABLE_INVOCATION_COUNTING` counter is off by default for latency.
- **Keep `socks_host` on the client at `127.0.0.1`** unless you specifically want LAN sharing.
- **Each Apps Script deployment is rate-limited to ~20,000 calls/day** on free Google accounts.

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
```

The harness compares your working tree against the committed baseline in `bench/baselines/` and prints a side-by-side table. Regressions above the noise floor fail the script with exit code 1. Include the output in your PR description.

To record a new baseline from a specific git ref:

```bash
bash bench/bench.sh --update <ref>   # e.g. --update v1.3.0 or --update HEAD
```

---

## Special Thanks

Special thanks to [@abolix](https://github.com/abolix) for making this project possible.

## License

MIT
