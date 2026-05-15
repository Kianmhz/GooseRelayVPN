# GooseRelayVPN Architecture

## Data Flow

```text
local app
  -> SOCKS5 listener
  -> session buffer and sequencing
  -> frame marshal
  -> AES-GCM batch envelope
  -> transport
       direct_stream: WebSocket /stream
       direct_post:   HTTP POST /tunnel
       apps_script:   Google Apps Script -> VPS /tunnel
  -> VPS exit session
  -> upstream TCP target
```

Apps Script is a compatibility fallback. It can only forward request/response
POST bodies, so persistent streaming is available only with direct VPS
transports.

## Main Components

- `cmd/client`: loads config, starts the local SOCKS5 listener, owns shutdown.
- `internal/socks`: adapts SOCKS5 connections onto tunnel sessions.
- `internal/session`: per-connection tx/rx buffering, FIN/RST handling, sequence
  ordering, and byte-aware draining.
- `internal/frame`: plaintext frame format plus AES-GCM batch encode/decode.
- `internal/carrier`: client-side transport selection, polling, endpoint
  scoring, quota handling, metrics, and stream reconnect loop.
- `cmd/server` and `internal/exit`: VPS HTTP/WebSocket endpoints, session
  demux, upstream dialing, downstream batching, GC, and stats.
- `apps_script/Code.gs`: stateless Google Apps Script forwarder.

## Session Lifecycle

1. Client creates a random 16-byte session ID.
2. First outbound frame carries `SYN` and the target `host:port`.
3. Server dials the upstream target and registers the session owner by client ID.
4. Data frames flow both directions with monotonically increasing sequence
   numbers per direction.
5. `FIN` requests graceful close; `RST` tears down state immediately.
6. Idle and done-session GC clean up orphaned sessions after disconnects.

## Operational Notes

- `transport_mode=auto` prefers direct stream when configured, then direct POST,
  then Apps Script.
- `max_sessions` caps total server sessions to protect a VPS from runaway
  clients or broken apps.
- Direct-stream disconnects keep sessions briefly so a quick reconnect does not
  destroy active connections.
- Apps Script quota is per Google account, not per deployment ID. Use account
  labels in `script_keys` when spreading quota across multiple accounts.
