#!/usr/bin/env bash
#
# bench.sh — drive the relay-tunnel benchmark harness and diff against a
# committed baseline.
#
# Usage:
#   ./bench/bench.sh                       # build HEAD, diff vs default baseline
#   ./bench/bench.sh --baseline v1.2.0     # diff against bench/baselines/v1.2.0.json
#   ./bench/bench.sh --update v1.3.0       # rebuild + re-record bench/baselines/v1.3.0.json
#   ./bench/bench.sh --scenario ttfb_p50_p95
#   ./bench/bench.sh --transport direct_stream
#   ./bench/bench.sh --smoke               # quick current-tree run, no baseline needed
#   ./bench/bench.sh --verbose             # stream child stdout/stderr
#
# Set BENCH_FAIL_THRESHOLD_PCT (default 10) to change the regression threshold.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
BENCH_DIR="$ROOT/bench"
BIN_DIR="$BENCH_DIR/bin"
BASELINES_DIR="$BENCH_DIR/baselines"
RESULTS_DIR="$BENCH_DIR/results"
WORKTREE_DIR="$BENCH_DIR/.worktrees"

mkdir -p "$BIN_DIR" "$BASELINES_DIR" "$RESULTS_DIR" "$WORKTREE_DIR"

DEFAULT_BASELINE="$({ git -C "$ROOT" tag --list 'v*' --sort=-version:refname 2>/dev/null || true; } | head -n 1)"

BASELINE=""
UPDATE_REF=""
SCENARIOS=""
TRANSPORT="direct_post"
VERBOSE=""
SMOKE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --baseline)
            BASELINE="${2:?missing ref for --baseline}"
            shift 2
            ;;
        --update)
            UPDATE_REF="${2:?missing ref for --update}"
            shift 2
            ;;
        --scenario|--scenarios)
            SCENARIOS="${2:?missing scenarios for --scenario}"
            shift 2
            ;;
        --transport)
            TRANSPORT="${2:?missing transport for --transport}"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE="-v"
            shift
            ;;
        --smoke)
            SMOKE="1"
            shift
            ;;
        -h|--help)
            sed -n '3,17p' "$0" | sed 's/^# *//'
            exit 0
            ;;
        *)
            echo "unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "$BASELINE" && -z "$UPDATE_REF" && -z "$SMOKE" ]]; then
    BASELINE="$DEFAULT_BASELINE"
fi

# ─── Build the bench tools (always against current source tree) ────────────
echo "==> building bench tools"
( cd "$ROOT" && \
    go build -o "$BIN_DIR/sink" ./bench/sink && \
    go build -o "$BIN_DIR/harness" ./bench/harness && \
    go build -o "$BIN_DIR/diff" ./bench/diff )

# ─── build_ref REF DEST_DIR — build goose-client and goose-server at REF ──
build_ref() {
    local ref="$1"
    local dest="$2"
    local src

    if [[ "$ref" == "HEAD" || "$ref" == "$(git -C "$ROOT" rev-parse HEAD)" || "$ref" == "$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)" ]]; then
        src="$ROOT"
        echo "==> building $ref from current tree"
    else
        local wt="$WORKTREE_DIR/$ref"
        if [[ ! -d "$wt/.git" && ! -f "$wt/.git" ]]; then
            echo "==> creating worktree for $ref at $wt"
            git -C "$ROOT" worktree add --detach "$wt" "$ref" >/dev/null
        else
            echo "==> reusing worktree for $ref at $wt"
            git -C "$wt" checkout --detach "$ref" >/dev/null 2>&1 || true
        fi
        src="$wt"
    fi

    mkdir -p "$dest"
    ( cd "$src" && \
        go build -trimpath -o "$dest/goose-client" ./cmd/client && \
        go build -trimpath -o "$dest/goose-server" ./cmd/server )
}

# ─── run_harness REF OUT_JSON BIN_DIR ─────────────────────────────────────
run_harness() {
    local ref="$1"
    local out="$2"
    local bins="$3"
    local commit
    local sha_args=("$ref")
    if [[ "$ref" == "HEAD" ]]; then
        sha_args=("HEAD")
    fi
    commit="$(git -C "$ROOT" rev-parse --short "${sha_args[@]}" 2>/dev/null || echo "")"

    echo "==> running harness for $ref (commit=$commit) → $out"
    "$BIN_DIR/harness" \
        --client-bin "$bins/goose-client" \
        --server-bin "$bins/goose-server" \
        --sink-bin "$BIN_DIR/sink" \
        --out "$out" \
        --ref "$ref" \
        --commit "$commit" \
        --transport "$TRANSPORT" \
        ${SCENARIOS:+--scenarios "$SCENARIOS"} \
        $VERBOSE
}

if [[ -n "$SMOKE" ]]; then
    HEAD_BIN="$BENCH_DIR/.smoke_bin"
    rm -rf "$HEAD_BIN"
    mkdir -p "$HEAD_BIN"
    echo "==> building current tree for smoke run"
    ( cd "$ROOT" && \
        go build -trimpath -o "$HEAD_BIN/goose-client" ./cmd/client && \
        go build -trimpath -o "$HEAD_BIN/goose-server" ./cmd/server )
    OUT="$RESULTS_DIR/smoke.json"
    if [[ -z "$SCENARIOS" ]]; then
        SCENARIOS="ttfb_p50_p95"
    fi
    run_harness "smoke" "$OUT" "$HEAD_BIN"
    echo
    echo "==> smoke results: $OUT"
    exit 0
fi

# ─── --update path: build the named ref, run, write to baselines/ ──────────
if [[ -n "$UPDATE_REF" ]]; then
    BASE_BIN="$WORKTREE_DIR/$UPDATE_REF/_bench_bin"
    rm -rf "$BASE_BIN"
    build_ref "$UPDATE_REF" "$BASE_BIN"
    OUT="$BASELINES_DIR/$UPDATE_REF.json"
    run_harness "$UPDATE_REF" "$OUT" "$BASE_BIN"
    echo
    echo "==> baseline updated: $OUT"
    exit 0
fi

# ─── default path: HEAD vs $BASELINE ───────────────────────────────────────
if [[ -z "$BASELINE" ]]; then
    echo "no baselines exist yet — run with --update <ref> first" >&2
    exit 2
fi

BASELINE_FILE="$BASELINES_DIR/$BASELINE.json"
if [[ ! -f "$BASELINE_FILE" ]]; then
    echo "baseline file not found: $BASELINE_FILE" >&2
    echo "run: ./bench/bench.sh --update $BASELINE" >&2
    exit 2
fi

HEAD_BIN="$BENCH_DIR/.head_bin"
rm -rf "$HEAD_BIN"
build_ref "HEAD" "$HEAD_BIN"

HEAD_SHORT="$(git -C "$ROOT" rev-parse --short HEAD)"
CURRENT_FILE="$RESULTS_DIR/$HEAD_SHORT.json"
run_harness "HEAD" "$CURRENT_FILE" "$HEAD_BIN"

echo
"$BIN_DIR/diff" "$BASELINE_FILE" "$CURRENT_FILE"
