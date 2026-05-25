# Real-World Testing Guide

This guide is for collecting useful evidence during Android/mobile and Apps
Script testing. It is not a benchmark scoreboard. The goal is to capture enough
client, server, and diagnostics data to explain stalls, quota events, local
network outages, and downstream replay behavior.

## Mobile-Safe Profile

Use this profile when Android reliability matters more than maximum raw speed.
It keeps replay opt-in, avoids unstable direct stream behavior on lossy links,
and limits the blast radius of a lost Google/mobile HTTP response.

Client:

```json
{
  "transport_mode": "apps_script",
  "downstream_replay_mode": "auto",
  "idle_poll_mode": "adaptive",
  "idle_slots_per_bucket": 1,
  "fronting_http_version": "auto",
  "stats_json": true,
  "write_startup_diagnostics": true
}
```

Server:

```json
{
  "downstream_replay_enabled": true,
  "max_response_bytes_pre_encode": 2097152,
  "second_response_bytes_pre_encode": 1048576,
  "stats_json": true,
  "write_startup_diagnostics": true
}
```

If downloads are stable and quota is healthy, test
`max_response_bytes_pre_encode: 4194304`, then `6291456`. With downstream
replay enabled, keep the response cap at or below `8388608` so one response
fits inside the per-session replay buffer. If downloads stall near the end or
Android memory looks stressed, return to `2097152`.

Startup ramp:

- The first downstream response for each session is capped at `524288` bytes.
- The second response ramps to `1048576` bytes by default. Try `2097152`
  only if Apps Script responses are stable and quota is healthy.
- Later responses use `max_response_bytes_pre_encode`.

This favors fast page/video startup before allowing bulk transfer size.

Transport reminder:

- For the safest censored/mobile test, use `transport_mode: "apps_script"` and
  leave `relay_urls` / `direct_stream_urls` empty.
- For direct stream testing, set `transport_mode: "auto"` or
  `transport_mode: "direct_stream"`, add `direct_stream_urls`, and keep
  `script_keys` as Apps Script POST fallback when using `auto`.
- For direct POST testing, set `transport_mode: "auto"` or
  `transport_mode: "direct_post"` and add `relay_urls`. In the current version,
  direct POST replaces Apps Script as the POST transport; it is not a second
  POST tier on top of `script_keys`.

## tmux Log Collection

On the VPS, start the server in tmux and tee logs to a timestamped file:

```bash
mkdir -p ~/goose-logs
ts=$(date +%Y%m%d_%H%M%S)
tmux new -s goose
./goose-server -config server_config.json 2>&1 | tee ~/goose-logs/server_$ts.log
```

Detach with `Ctrl-b`, then `d`. Reattach later:

```bash
tmux attach -t goose
```

If the server is already running in tmux, capture the pane:

```bash
mkdir -p ~/goose-logs
tmux capture-pane -t goose -p -S -20000 > ~/goose-logs/server_$(date +%Y%m%d_%H%M%S)_capture.log
```

## Client Log Collection

On Windows PowerShell:

```powershell
$ts = Get-Date -Format yyyyMMdd_HHmmss
New-Item -ItemType Directory -Force -Path .\dist\diagnostics | Out-Null
.\goose-client.exe -config client_config.json *> ".\dist\client_$ts.log"
```

On Android/Termux:

```bash
mkdir -p ~/goose-logs
ts=$(date +%Y%m%d_%H%M%S)
./goose-client -config client_config.json 2>&1 | tee ~/goose-logs/client_$ts.log
```

On Windows, `go test -race` needs a GCC toolchain. If MSYS2 UCRT is first in
PATH and race tests fail at link time, put MinGW64 first for that terminal:

```powershell
$env:Path = "C:\msys64\mingw64\bin;$env:Path"
go test -race -count=1 ./...
```

## Diagnostics Zips

If `write_startup_diagnostics` is true, both binaries write a redacted
diagnostics zip on startup. For a manual one-shot capture:

```bash
./goose-client -config client_config.json -dump-diag
./goose-server -config server_config.json -dump-diag
```

Use `-diag-output path/to/file.zip` when you want a specific output path.
For live profiling during a test, start either binary with a loopback pprof
listener:

```bash
./goose-client -config client_config.json -debug-pprof 127.0.0.1:6060 -stats-json
./goose-server -config server_config.json -debug-pprof 127.0.0.1:6061 -stats-json
```

Then keep:

- client terminal log,
- server terminal log,
- client diagnostics zip,
- server diagnostics zip,
- client/server configs with `tunnel_key`, deployment IDs, URLs, and proxy
  secrets removed.

## What Healthy Looks Like

Healthy Apps Script/direct POST:

- client pre-flight succeeds,
- `[stats] endpoints` shows at least one healthy endpoint,
- useful polls increase during browsing/downloads,
- empty polls increase while idle,
- no repeated `empty_204`, `decode_error`, `non_batch`, or `quota` reasons.

Healthy downstream replay:

- client stats show `replay active=true` after negotiation,
- server stats show `replay enabled=true`,
- `ack_sent` and `ack_received` increase during downloads,
- occasional `replay frames/bytes` is acceptable on bad mobile networks,
- `dropped_sessions` should stay zero in normal use.

## Failure Patterns

Quota:

- `quota exhausted`,
- `Service invoked too many times`,
- endpoint reason `quota`.

Bad key/deployment/protocol:

- direct `HTTP 204`,
- `empty 200 response`,
- `message authentication failed`,
- endpoint reason `empty_204` or `decode_error`.

Local phone/network outage:

- `network is unreachable`,
- `network is down`,
- `no route to host`,
- `local network offline`.

Google/fronting instability:

- very high `poll rtt`,
- `http2: client connection lost`,
- repeated relay response read failures.

Android receive pressure:

- `rx_inbox_timeout`,
- repeated `rx_reorder_overflow`,
- replay cap drops,
- Android/Termux killed by the OS.

## Analyzer

Run:

```bash
go run ./cmd/analyze -- client.log server.log
```

Use the recommendations as triage:

- replay-off plus `rx_reorder_overflow`: enable the mobile replay profile,
- replay cap drops: lower server response size before raising memory caps,
- HTTP/2/fronting instability: test `fronting_http_version: "h1"`,
- idle quota burn: test `idle_poll_mode: "adaptive"` or `"off"`,
- quota evidence: add distinct Google accounts, not just more deployments.

## Real-World Test Script

Run one clean session for each transport/profile:

1. Start server and client with `stats_json` and startup diagnostics enabled.
2. Browse 5-10 normal sites.
3. Open Telegram/X/Google Play and let background traffic run for 5 minutes.
4. Download a 200 MB file.
5. Toggle airplane mode for 30-60 seconds while idle.
6. Toggle airplane mode during a download.
7. Capture logs and diagnostics before restarting anything.

Do not redeploy Apps Script during the test unless you are specifically testing
bad deployment recovery. Redeploying changes the evidence trail.
