// diff prints a side-by-side comparison of two harness result JSON files and
// exits 1 if any tracked metric regresses by more than the threshold percentage.
//
// Tracked metrics per scenario (others are ignored — only "headline" numbers
// drive pass/fail):
//
//	throughput_*      mb_per_sec       (higher is better)
//	ttfb_p50_p95      p50_us, p95_us, p99_us (lower is better)
//	sessions_per_sec  per_sec, fail    (speed higher is better; failures lower)
//	idle_overhead_15s client_cpu_mean, server_cpu_mean (lower is better)
//	download_first_byte_* first_byte_us (lower is better)
//	download_pause_at_97pct_8MB after_pause_ms (lower), post_pause_mb_sec (higher)
//	browsing_latency_while_download_active nested ttfb metrics
//	mixed_stream_bad_syn_bulk nested ttfb/download metrics
//
// The threshold is read from BENCH_FAIL_THRESHOLD_PCT (default 10).
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

type direction int

const (
	higherBetter direction = iota
	lowerBetter
)

type metric struct {
	scenario string
	field    string
	dir      direction
	unit     string
	// noiseFloor: if both baseline and current are at or below this absolute
	// value, the metric is treated as below the measurement floor — printed for
	// information but exempt from the regression threshold. Set per-metric
	// because "noise" is unit-dependent (0.5% CPU ≈ noise, but 0.5 MB/s isn't).
	noiseFloor float64
}

var trackedMetrics = []metric{
	{"throughput_up_1MB_1session", "mb_per_sec", higherBetter, "MB/s", 0},
	{"throughput_up_8MB_1session", "mb_per_sec", higherBetter, "MB/s", 0},
	{"throughput_up_8MB_4sessions", "mb_per_sec", higherBetter, "MB/s", 0},
	{"throughput_down_8MB_1session", "mb_per_sec", higherBetter, "MB/s", 0},
	{"ttfb_p50_p95", "p50_us", lowerBetter, "µs", 0},
	{"ttfb_p50_p95", "p95_us", lowerBetter, "µs", 0},
	{"ttfb_p50_p95", "p99_us", lowerBetter, "µs", 0},
	{"sessions_per_sec", "per_sec", higherBetter, "/s", 0},
	{"sessions_per_sec", "fail", lowerBetter, "fail", 0},
	// CPU% sampling jitter is ~0.1pp at idle. Treat sub-1% as noise so a
	// baseline of 0.07% vs current of 0.11% doesn't read as a 57% regression.
	{"idle_overhead_15s", "client_cpu_mean", lowerBetter, "%", 1.0},
	{"idle_overhead_15s", "server_cpu_mean", lowerBetter, "%", 1.0},
	{"download_first_byte_8MB", "first_byte_us", lowerBetter, "µs", 0},
	{"download_first_byte_16MB", "first_byte_us", lowerBetter, "µs", 0},
	{"download_pause_at_97pct_8MB", "after_pause_ms", lowerBetter, "ms", 10},
	{"download_pause_at_97pct_8MB", "post_pause_mb_sec", higherBetter, "MB/s", 0},
	{"browsing_latency_while_download_active", "ttfb.p95_us", lowerBetter, "µs", 0},
	{"browsing_latency_while_download_active", "ttfb.p99_us", lowerBetter, "µs", 0},
	{"mixed_stream_bad_syn_bulk", "duration_ms", lowerBetter, "ms", 0},
	{"mixed_stream_bad_syn_bulk", "ttfb.p95_us", lowerBetter, "µs", 0},
	{"mixed_stream_bad_syn_bulk", "download.mb_per_sec", higherBetter, "MB/s", 0},
}

type results struct {
	Ref            string                     `json:"ref"`
	Commit         string                     `json:"commit"`
	Host           map[string]any             `json:"host"`
	Metadata       map[string]any             `json:"metadata"`
	ScenarioSubset bool                       `json:"scenario_subset"`
	Scenarios      map[string]json.RawMessage `json:"scenarios"`
}

func main() {
	threshold := envFloat("BENCH_FAIL_THRESHOLD_PCT", 10.0)

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: diff BASELINE_JSON CURRENT_JSON")
	}
	flag.Parse()
	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}
	baseline := mustLoad(flag.Arg(0))
	current := mustLoad(flag.Arg(1))

	hostsMatch := fmt.Sprint(baseline.Host) == fmt.Sprint(current.Host)
	if !hostsMatch {
		fmt.Fprintf(os.Stderr, "WARN: host info differs between baseline and current — absolute numbers may not compare\n")
		fmt.Fprintf(os.Stderr, "  baseline: %v\n", baseline.Host)
		fmt.Fprintf(os.Stderr, "  current : %v\n", current.Host)
	}

	if warning := benchmarkMetadataWarning(baseline, current); warning != "" {
		fmt.Fprintln(os.Stderr, warning)
	}

	fmt.Printf("baseline: %s (%s)\n", baseline.Ref, shortCommit(baseline.Commit))
	fmt.Printf("current : %s (%s)\n", current.Ref, shortCommit(current.Commit))
	fmt.Printf("threshold: %.1f%% per-metric regression fails this run\n\n", threshold)

	header := fmt.Sprintf("%-44s %16s %16s %10s %s", "METRIC", "BASELINE", "CURRENT", "Δ", "")
	fmt.Println(header)
	fmt.Println(strings.Repeat("-", len(header)))

	regressions := 0
	currentSubset := current.ScenarioSubset
	for _, m := range trackedMetrics {
		bRaw, bok := baseline.Scenarios[m.scenario]
		cRaw, cok := current.Scenarios[m.scenario]
		if !bok && !cok {
			continue
		}
		bv, bvok := extractField(bRaw, m.field)
		cv, cvok := extractField(cRaw, m.field)
		label := fmt.Sprintf("%s.%s", m.scenario, m.field)
		switch {
		case !bvok && !cvok:
			continue
		case !bvok:
			fmt.Printf("%-44s %16s %16s %10s\n", label, "—", formatVal(cv, m.unit), "(new)")
		case !cvok:
			if currentMetricUnavailable(cRaw, m.field) {
				fmt.Printf("%-44s %16s %16s %10s\n", label, formatVal(bv, m.unit), "—", "(unavailable)")
				continue
			}
			status, countsAsRegression := missingCurrentMetricStatus(currentSubset && !cok)
			if countsAsRegression {
				regressions++
			}
			fmt.Printf("%-44s %16s %16s %10s\n", label, formatVal(bv, m.unit), "—", status)
		default:
			deltaPct := percentDelta(bv, cv)
			belowFloor := m.noiseFloor > 0 && bv <= m.noiseFloor && cv <= m.noiseFloor
			marker := ""
			regressed := false
			if belowFloor {
				marker = "(below noise floor)"
			} else {
				marker, regressed = classify(m.dir, deltaPct, threshold)
			}
			fmt.Printf("%-44s %16s %16s %+9.1f%% %s\n",
				label,
				formatVal(bv, m.unit),
				formatVal(cv, m.unit),
				deltaPct,
				marker,
			)
			if regressed {
				regressions++
			}
		}
	}

	fmt.Println()
	if regressions > 0 {
		fmt.Printf("✗ %d metric(s) regressed by more than %.1f%% — failing\n", regressions, threshold)
		os.Exit(1)
	}
	fmt.Println("✓ no regressions over threshold")
}

func missingCurrentMetricStatus(scenarioNotRun bool) (string, bool) {
	if scenarioNotRun {
		return "(not run)", false
	}
	return "(missing)", true
}

func benchmarkMetadataWarning(baseline, current results) string {
	if len(baseline.Metadata) == 0 || len(current.Metadata) == 0 {
		return "WARN: benchmark metadata missing from baseline or current - confirm transport/impairment/config manually"
	}
	b, berr := json.Marshal(baseline.Metadata)
	c, cerr := json.Marshal(current.Metadata)
	if berr != nil || cerr != nil {
		return "WARN: benchmark metadata could not be normalized - confirm transport/impairment/config manually"
	}
	if !bytes.Equal(b, c) {
		return fmt.Sprintf("WARN: benchmark metadata differs between baseline and current - results may not compare\n  baseline: %s\n  current : %s", b, c)
	}
	return ""
}

func currentMetricUnavailable(raw json.RawMessage, field string) bool {
	if raw == nil || !strings.Contains(field, "cpu_") {
		return false
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return false
	}
	unavailable, _ := obj["cpu_unavailable"].(bool)
	return unavailable
}

func mustLoad(path string) results {
	body, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(2)
	}
	var r results
	if err := json.Unmarshal(body, &r); err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", path, err)
		os.Exit(2)
	}
	return r
}

func extractField(raw json.RawMessage, field string) (float64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0, false
	}
	var v any = m
	for _, part := range strings.Split(field, ".") {
		obj, ok := v.(map[string]any)
		if !ok {
			return 0, false
		}
		v, ok = obj[part]
		if !ok {
			return 0, false
		}
	}
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return 0, false
		}
		return f, true
	default:
		return 0, false
	}
}

func percentDelta(baseline, current float64) float64 {
	if baseline == 0 {
		if current == 0 {
			return 0
		}
		return math.Inf(1)
	}
	return (current - baseline) / baseline * 100.0
}

func classify(dir direction, deltaPct, threshold float64) (string, bool) {
	switch dir {
	case higherBetter:
		if deltaPct < -threshold {
			return "✗ REGRESSION", true
		}
		if deltaPct > threshold {
			return "✓ improvement", false
		}
	case lowerBetter:
		if deltaPct > threshold {
			return "✗ REGRESSION", true
		}
		if deltaPct < -threshold {
			return "✓ improvement", false
		}
	}
	return "", false
}

func formatVal(v float64, unit string) string {
	switch unit {
	case "MB/s", "%":
		return fmt.Sprintf("%.2f %s", v, unit)
	case "/s":
		return fmt.Sprintf("%.1f %s", v, unit)
	case "µs":
		if v >= 1000 {
			return fmt.Sprintf("%.2f ms", v/1000)
		}
		return fmt.Sprintf("%.0f %s", v, unit)
	case "ms":
		return fmt.Sprintf("%.0f %s", v, unit)
	default:
		return fmt.Sprintf("%v %s", v, unit)
	}
}

func envFloat(name string, fallback float64) float64 {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

func shortCommit(c string) string {
	if len(c) > 8 {
		return c[:8]
	}
	return c
}
