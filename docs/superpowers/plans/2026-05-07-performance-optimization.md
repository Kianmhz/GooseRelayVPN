# GooseRelayVPN Performance Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add verified speed-focused foundations, scheduling improvements, metrics, adaptive behavior, and a direct-streaming path without breaking the existing Apps Script relay.

**Architecture:** Implement in vertical slices. First add shared limits and config profiles, then byte-aware scheduling and endpoint tuning, then metrics/compression, then direct streaming and binary direct encoding. Existing Apps Script behavior remains the fallback.

**Tech Stack:** Go standard library, existing `internal/frame`, `internal/session`, `internal/carrier`, `internal/exit`, Apps Script JavaScript, existing `go test` suite.

---

### Task 1: Shared Limits And Configurable Fast Defaults

**Files:**
- Modify: `internal/protocol/protocol.go`
- Modify: `internal/config/client.go`
- Modify: `internal/config/server.go`
- Modify: `internal/carrier/client.go`
- Modify: `internal/exit/exit.go`
- Test: `internal/config/client_test.go`
- Test: `internal/config/server_test.go`

- [ ] Add protocol constants for shared frame, batch, and byte budgets.
- [ ] Add `performance_mode` parsing with accepted values `balanced`, `latency`, and `throughput`.
- [ ] Add client config fields for worker policy, poll idle sleep, blacklist TTLs, and request byte budget.
- [ ] Add server config fields for active drain, long poll, coalesce windows, and response byte budget.
- [ ] Keep current behavior as balanced defaults.
- [ ] Write config tests first, verify they fail, implement, then run `go test -count=1 ./internal/config`.

### Task 2: Hard-Limited Relay Body Reads

**Files:**
- Modify: `internal/carrier/client.go`
- Modify: `internal/exit/exit.go`
- Test: `internal/carrier/client_test.go`
- Test: `internal/exit/exit_timing_test.go`

- [ ] Add tests proving oversized response/request bodies are rejected while normal bodies still decode.
- [ ] Replace raw `io.ReadAll` calls with `io.LimitedReader` helpers.
- [ ] Run targeted tests and then `go test -count=1 ./internal/carrier ./internal/exit`.

### Task 3: Byte-Aware Session Draining

**Files:**
- Modify: `internal/session/session.go`
- Modify: `internal/carrier/client.go`
- Modify: `internal/exit/exit.go`
- Test: `internal/session/session_test.go`
- Test: `internal/carrier/client_test.go`
- Test: `internal/exit/exit_timing_test.go`

- [ ] Add a failing session test for frame cap plus byte cap preserving per-session ordering.
- [ ] Add `DrainTxLimitedByBudget(maxFramePayload, maxFrames, maxBytes int)`.
- [ ] Use byte-aware draining in carrier and exit batch builders.
- [ ] Keep existing `DrainTxLimited` as a compatibility wrapper.
- [ ] Run `go test -count=1 ./internal/session ./internal/carrier ./internal/exit`.

### Task 4: Urgent Wake And Fast Lanes

**Files:**
- Modify: `internal/carrier/client.go`
- Modify: `internal/exit/exit.go`
- Test: `internal/carrier/client_test.go`
- Test: `internal/exit/exit_timing_test.go`

- [ ] Add tests showing urgent carrier kicks bypass coalescing.
- [ ] Mark SYN/control/first-reply/RST/version-response traffic urgent.
- [ ] Ensure urgent exit batches keep skipping coalesce.
- [ ] Run targeted tests and full `go test -count=1 ./...`.

### Task 5: Endpoint RTT Scoring And Dynamic Idle Polling

**Files:**
- Modify: `internal/carrier/client.go`
- Test: `internal/carrier/client_test.go`

- [ ] Add tests for RTT EWMA scoring, slow penalty, blacklist fallback, and round-robin tie breaks.
- [ ] Track RTT on successful relay calls and separate slow-response penalty from hard failures.
- [ ] Prefer recently non-empty endpoints for downstream-heavy traffic.
- [ ] Add dynamic idle slot logic based on active downstream pressure.
- [ ] Run `go test -count=1 ./internal/carrier`.

### Task 6: Adaptive Compression And Metrics

**Files:**
- Modify: `internal/frame/crypto.go`
- Modify: `internal/carrier/stats.go`
- Modify: `internal/exit/stats.go`
- Test: `internal/frame/crypto_test.go`

- [ ] Add tests for poor-ratio compression bypass.
- [ ] Track compression ratio per batch and expose counters.
- [ ] Cache per-session compression decision after enough samples.
- [ ] Add latency mode lower-cost compression behavior.
- [ ] Run `go test -count=1 ./internal/frame ./internal/carrier ./internal/exit`.

### Task 7: Benchmark Smoke And Latency Scenarios

**Files:**
- Modify: `bench/bench.sh`
- Modify: `bench/harness/main.go`
- Modify: `bench/README.md`

- [ ] Add `--smoke` mode that runs quickly on local machines.
- [ ] Add scenarios for 1-byte latency under load, short sessions, mixed chat plus download, and artificial RTT.
- [ ] Add p50/p95 latency threshold hooks without making CI flaky by default.
- [ ] Run `bash bench/bench.sh --smoke` where Bash is available.

### Task 8: Direct Streaming Transport

**Files:**
- Create: `internal/transport/transport.go`
- Create: `internal/transport/post.go`
- Create: `internal/transport/websocket.go`
- Modify: `internal/carrier/client.go`
- Modify: `internal/exit/exit.go`
- Modify: `go.mod`

- [ ] Introduce a transport interface that can carry encrypted frame batches.
- [ ] Move existing HTTP POST exchange behind the interface.
- [ ] Add WebSocket direct mode for direct VPS endpoints.
- [ ] Keep Apps Script on POST transport.
- [ ] Add direct-first fallback to POST/Apps Script.
- [ ] Run direct-mode integration tests through the bench harness.

### Task 9: Direct Binary Wire Format

**Files:**
- Create: `internal/frame/binary.go`
- Modify: `internal/frame/frame.go`
- Modify: `internal/frame/crypto.go`
- Modify: `internal/protocol/protocol.go`
- Test: `internal/frame/frame_test.go`
- Test: `internal/frame/crypto_test.go`

- [ ] Add capability negotiation for direct binary batches.
- [ ] Keep base64 text envelope for Apps Script.
- [ ] Encode direct batches as binary request/response bodies.
- [ ] Add compact frame forms only after direct streaming is stable.
- [ ] Run `go test -count=1 ./internal/frame ./internal/protocol`.

### Task 10: Auto-Tuning

**Files:**
- Modify: `internal/carrier/client.go`
- Modify: `internal/carrier/stats.go`
- Modify: `internal/exit/exit.go`

- [ ] Use collected metrics to tune idle slots, coalesce windows, batch caps, and compression choices.
- [ ] Keep profile settings as hard bounds so auto-tuning cannot explode concurrency.
- [ ] Add tests for conservative fallback when metrics are absent.
- [ ] Run `go test -count=1 ./...`.

## Verification

Every task ends with targeted tests. The final gate is:

```powershell
go test -count=1 ./...
```

Race verification is:

```powershell
$env:CGO_ENABLED='1'; go test -race -count=1 -timeout 90s ./...
```

On this Windows workspace, `go test -race` requires CGO support.
