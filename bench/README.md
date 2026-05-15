# Bench

Loopback end-to-end benchmark harness for relay-tunnel. Runs `goose-client`
and `goose-server` locally, pointing the client at the server directly via the
`relay_urls` config affordance — Apps Script is deliberately excluded so
results are reproducible and reflect code changes, not Google's CDN behaviour.

## Quick start

```sh
# First time: capture a baseline for the current release.
./bench/bench.sh --update v1.3.0

# Day-to-day: build HEAD, run the harness, diff against the latest baseline.
./bench/bench.sh
```

The diff exits 0 when nothing regresses by more than 10% (set
`BENCH_FAIL_THRESHOLD_PCT=N` to change the threshold), and 1 otherwise. Wire it
into your pre-tag flow when you're ready.

## Useful flags

```sh
./bench/bench.sh --baseline v1.2.0
./bench/bench.sh --scenario ttfb_p50_p95
./bench/bench.sh --scenario ttfb_p50_p95 --transport direct_stream
./bench/bench.sh --scenario throughput_up_64MB_1session,sessions_per_sec
./bench/bench.sh --verbose                    # stream child stdout/stderr
./bench/bench.sh --update v1.3.0              # re-record a baseline
```

## Scenarios

| Name | What it measures | Headline metric |
| --- | --- | --- |
| `throughput_up_1MB_1session` | Single SOCKS session, 1 MB upload to sized sink | `mb_per_sec` |
| `throughput_up_8MB_1session` | Single session, 8 MB upload | `mb_per_sec` |
| `throughput_up_8MB_4sessions` | 4 concurrent sessions, 8 MB each | `mb_per_sec` |
| `throughput_down_8MB_1session` | Single session, 8 MB download from source sink | `mb_per_sec` |
| `ttfb_p50_p95` | 50 sequential 1-byte echoes, latency percentiles | `p50_us`, `p95_us`, `p99_us` |
| `sessions_per_sec` | Open/close churn against quick sink for 10 s | `per_sec` |
| `idle_overhead_15s` | 50 idle echo connections; sample CPU% every 500 ms | `client_cpu_mean`, `server_cpu_mean` |
| `mixed_stream_bad_syn_bulk` | One bad SYN target while short echoes and a 1 MB download run | `duration_ms`, nested TTFB/download metrics |

Throughput numbers are bounded by `ActiveDrainWindow` (350 ms) — every HTTP round-trip costs at least one window, so a single-session upload caps at roughly `MaxFramePayload × maxDrainFramesPerSession / ActiveDrainWindow` ≈ 6 MB/s. Sizes above are tuned so the full suite finishes in ~90 s.

## Transport Comparison

Run latency scenarios once with `--transport direct_post` and once with
`--transport direct_stream` to compare direct POST TTFB against the persistent
WebSocket stream path on the same machine.

## Layout

```
bench/
├── bench.sh           # entry point: builds + runs + diffs
├── harness/           # spawns sink/server/client, runs scenarios, emits JSON
├── sink/              # 4 TCP modes on :9101–:9104
├── diff/              # baseline-vs-current diff with pass/fail
├── baselines/         # committed JSON, one file per release tag
├── results/           # per-run JSON (gitignored)
├── bin/               # built bench tools (gitignored)
└── .worktrees/        # transient git worktrees for non-HEAD builds (gitignored)
```

## Important: baselines are machine-specific

Absolute numbers depend on the host (CPU, kernel, scheduler load). Always
re-record baselines on the same machine you're running comparisons from. If
you switch laptops or run on a server, regenerate every baseline you care
about.

## Caveats

* Apps Script is excluded — this harness does **not** measure Google's CDN
  variance, only relay-tunnel code paths. For absolute throughput reality
  checks, run a real deployment instead.
* The harness uses `ps -o %cpu=` to sample idle CPU. This is fine for
  regression detection (variance is usually < 0.5 percentage points on a quiet
  machine) but not a precise profiling tool.
* Scenarios run once each. If you want statistical confidence, run the script
  several times and eyeball the spread.
