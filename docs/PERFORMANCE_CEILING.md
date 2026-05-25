# GooseRelayVPN Performance Ceiling

This project can reduce waste around Apps Script, but it cannot remove Apps
Script's fixed relay latency. In Apps Script mode, every tunnel exchange takes
roughly this route:

```text
local app -> local SOCKS -> Goose client -> Google edge -> Apps Script
  -> VPS /tunnel -> target website
```

The Google edge and Apps Script hop adds a large fixed round trip before the
VPS can return data. Code changes can still help by:

- keeping standing long-polls available for downstream data;
- packing enough bytes into each request without exceeding Apps Script limits;
- avoiding slow or quota-exhausted deployment IDs;
- skipping unnecessary compression for encrypted payloads;
- reducing client/server coalescing delays for interactive traffic;
- choosing a lower-latency `google_host` and SNI set.

Code changes cannot make `UrlFetchApp.fetch()` behave like a persistent TCP
stream. Direct stream mode is the architectural path with the lowest latency,
but it only helps where direct VPS WebSocket access is not blocked.

For Apps Script-only use, the practical low-latency profile is:

```json
{
  "performance_mode": "latency",
  "coalesce_step_ms": 0,
  "poll_idle_sleep_ms": 5,
  "idle_poll_mode": "adaptive",
  "idle_slots_per_bucket": 1
}
```

Server-side:

```json
{
  "performance_mode": "latency",
  "active_drain_window_ms": 150,
  "long_poll_window_ms": 8000,
  "coalesce_window_ms": 0,
  "coalesce_window_busy_ms": 0
}
```

If testing shows slow browsing despite these values, the highest-yield checks
are usually outside the batch encoder:

1. Try several Google edge IPs for `google_host` and keep the lowest-RTT one.
2. Add more Apps Script deployments on separate Google accounts.
3. Check client stats for quota exhaustion, blacklisting, empty-poll ratio, and
   endpoint RTT.
4. On the VPS, use an upstream proxy such as WARP for sites that dislike
   datacenter IPs.
