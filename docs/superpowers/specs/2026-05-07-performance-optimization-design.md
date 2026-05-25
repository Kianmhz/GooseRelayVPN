# GooseRelayVPN Performance Optimization Design

## Goal

Move GooseRelayVPN toward the lowest practical latency and highest practical throughput while preserving the current Apps Script relay path as a compatibility fallback.

The main target is speed. Security, privacy, and stealth are not optimized in this design except where existing behavior must remain compatible.

## Current System

The client accepts local SOCKS5 TCP connections, converts stream data into framed sessions, encrypts and optionally compresses frame batches, then sends those batches to the exit server. The current common path is HTTP POST through an Apps Script forwarder. The exit server decrypts frames, opens upstream TCP connections, and returns downstream frames through long-poll responses.

The current direct `relay_urls` path avoids Apps Script but still uses the same HTTP POST batch exchange. It is not a first-class streaming transport.

## Performance Limits

The confirmed performance ceilings are:

- Apps Script forwarding adds invocation overhead, extra HTTP request cost, and long-poll timing limits.
- The batch scheduler is mostly frame-count based, so large frames can delay small interactive traffic.
- Endpoint selection is round-robin with blacklist behavior, not latency weighted.
- Coalesce, long-poll, active-drain, worker, and idle-poll timing are mostly hardcoded.
- Compression is static: it avoids small batches and rejects larger compressed output, but it does not learn per-session or per-batch traffic type.
- Metrics and benchmarks are not detailed enough to safely auto-tune latency-sensitive behavior.

## Architecture

Implementation will be staged so every stage is testable and compatible with existing clients and servers.

### Stage 1: Tunable Fast Foundations

Centralize shared protocol limits and expose performance-related knobs through config defaults and profiles:

- `performance_mode`: `balanced`, `latency`, or `throughput`.
- Active drain window.
- Long-poll window.
- Server coalesce windows.
- Account-bucket worker policy.
- Client idle-poll sleep.
- Endpoint blacklist TTLs.
- Client request byte budget, symmetric with server response byte budget.

The default mode keeps current behavior unless a mode explicitly changes a value.

Apps Script invocation counting will become optional and disabled by default for performance deployments.

### Stage 2: Latency-Aware Scheduler

Add scheduler behavior that protects small and urgent traffic from bulk transfers:

- Carrier and exit byte-aware draining.
- Per-session frame and byte budgets.
- Urgent queues for control, RST, version response, SYN, and first downstream reply.
- Carrier wakeups that can bypass coalescing for urgent traffic.
- Dynamic drain and coalesce behavior when SYN backlog is high.
- Larger batches only when traffic is clearly bulk and no urgent work is pending.

The scheduler must preserve per-session ordering. It must not sort frames within a session by payload size.

### Stage 3: Adaptive Endpoint And Idle Polling

Endpoint choice will include runtime observations:

- RTT EWMA per endpoint.
- Slow-response penalty separate from hard failure blacklist.
- Preference for endpoints that recently returned useful downstream data.
- Dynamic idle long-poll slots based on active downstream pressure.
- p50/p95 endpoint stats for diagnostics.

This keeps round-robin only as a fallback/tie-breaker.

### Stage 4: Adaptive Compression And Metrics

Compression should become data-driven:

- Track compression ratio per batch and per session.
- Skip zstd for high-entropy or consistently bad-ratio streams.
- Use lower-latency compression settings in latency mode.
- Keep current raw fallback when compressed output is not smaller.

Metrics needed before auto-tuning:

- p50/p95/p99 first-byte latency.
- Per-stage timing: queue wait, encode, HTTP/transport RTT, decode, route, deliver.
- Request and response payload-size histograms.
- Encode/decode allocation benchmarks.
- Benchmarks for 1-byte latency under load, 100 short sessions, mixed chat plus download, artificial RTT, and Apps Script long-poll simulation.

### Stage 5: Direct Streaming Transport

Add a first-class direct VPS streaming transport before changing the direct wire format.

Recommended first implementation: WebSocket direct mode.

Reasons:

- It supports bidirectional streaming over one connection.
- It is easier to test than a custom HTTP/2 streaming design.
- It can coexist with the existing HTTP POST transport.
- It gives most of the latency gain by eliminating repeated POST/long-poll exchange overhead.

The client should try direct streaming first when configured, then fall back to existing direct HTTP POST or Apps Script forwarding.

### Stage 6: Binary Direct Wire Format

Once direct streaming exists, add a direct-only binary batch format:

- Keep base64 envelope for Apps Script compatibility.
- Use binary bodies for direct transport.
- Add capability negotiation so old clients and servers remain compatible.
- Consider compact frame forms only after streaming mode is stable.

## Error Handling

Performance features must fail closed to existing behavior:

- Unknown `performance_mode` values should be rejected by config parsing.
- Invalid durations and limits should either default or produce config errors, following existing config style.
- If direct streaming fails to connect or negotiate, the client should fall back to configured existing transports.
- If adaptive compression cannot classify traffic, it should use current compression behavior.
- If endpoint metrics are missing, selection should use existing healthy endpoint logic.

## Testing

Use test-first implementation for behavior changes.

Required tests:

- Config parsing for all new knobs and profiles.
- Request and response body hard-limit behavior.
- Byte-aware session draining that preserves per-session order.
- Urgent wake/coalesce bypass.
- Endpoint RTT scoring and tie-breaking.
- Adaptive compression decisions.
- Benchmark smoke mode.
- Transport fallback decisions.

Full verification remains `go test -count=1 ./...`. Race tests are desirable, but this Windows environment needs CGO enabled for `go test -race`.

## Non-Goals

This design does not promise that every item lands in one patch. The transport rewrite and binary format are larger than the config/scheduler/metrics changes and should land after the benchmark and metric foundations.

This design does not optimize for stealth, privacy, or security beyond keeping the existing tunnel functional.

## Self-Review

The design is intentionally staged. No stage requires breaking Apps Script compatibility. The direct binary format depends on direct streaming transport and is not introduced first. Scheduler changes explicitly preserve per-session ordering to avoid the main correctness hazard in size-prioritized draining.
