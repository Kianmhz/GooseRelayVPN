package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestExtractFieldSupportsDotPath(t *testing.T) {
	raw := json.RawMessage(`{"ttfb":{"p95_us":1200},"download":{"mb_per_sec":3.5}}`)
	got, ok := extractField(raw, "ttfb.p95_us")
	if !ok {
		t.Fatal("extractField did not find nested dot-path metric")
	}
	if got != 1200 {
		t.Fatalf("extractField = %v, want 1200", got)
	}
}

func TestTrackedMetricsIncludeRealPainScenarios(t *testing.T) {
	want := []string{
		"download_first_byte_8MB.first_byte_us",
		"download_first_byte_16MB.first_byte_us",
		"download_pause_at_97pct_8MB.after_pause_ms",
		"download_pause_at_97pct_8MB.post_pause_mb_sec",
		"browsing_latency_while_download_active.ttfb.p95_us",
		"sessions_per_sec.fail",
		"mixed_stream_bad_syn_bulk.ttfb.p95_us",
		"mixed_stream_bad_syn_bulk.download.mb_per_sec",
	}
	have := make(map[string]bool, len(trackedMetrics))
	for _, m := range trackedMetrics {
		have[m.scenario+"."+m.field] = true
	}
	for _, key := range want {
		if !have[key] {
			t.Fatalf("trackedMetrics missing %s", key)
		}
	}
}

func TestPauseAfterResumeMetricHasNoiseFloor(t *testing.T) {
	for _, m := range trackedMetrics {
		if m.scenario == "download_pause_at_97pct_8MB" && m.field == "after_pause_ms" {
			if m.noiseFloor < 1 {
				t.Fatal("after_pause_ms needs a small noise floor so a zero baseline does not false-fail on 1ms jitter")
			}
			return
		}
	}
	t.Fatal("after_pause_ms metric was not tracked")
}

func TestMissingScenarioInSubsetIsNotRegression(t *testing.T) {
	status, regressed := missingCurrentMetricStatus(true)
	if status != "(not run)" || regressed {
		t.Fatalf("subset missing scenario status = %q, %v; want not run/non-regression", status, regressed)
	}
	status, regressed = missingCurrentMetricStatus(false)
	if status != "(missing)" || !regressed {
		t.Fatalf("scenario ran with missing metric status = %q, %v; want missing/regression", status, regressed)
	}
}

func TestCurrentMetricUnavailableOnlyAppliesToCPUFields(t *testing.T) {
	raw := json.RawMessage(`{"cpu_unavailable":true}`)
	if !currentMetricUnavailable(raw, "client_cpu_mean") {
		t.Fatal("CPU field should be unavailable when scenario says cpu_unavailable")
	}
	if currentMetricUnavailable(raw, "p50_us") {
		t.Fatal("non-CPU field should not be treated as unavailable")
	}
}

func TestBenchmarkMetadataWarning(t *testing.T) {
	base := results{Metadata: map[string]any{
		"transport":  "direct_post",
		"impairment": "none",
	}}
	same := results{Metadata: map[string]any{
		"transport":  "direct_post",
		"impairment": "none",
	}}
	if got := benchmarkMetadataWarning(base, same); got != "" {
		t.Fatalf("matching metadata warning = %q, want empty", got)
	}

	mismatch := results{Metadata: map[string]any{
		"transport":  "direct_stream",
		"impairment": "none",
	}}
	if got := benchmarkMetadataWarning(base, mismatch); !strings.Contains(got, "metadata differs") {
		t.Fatalf("mismatch warning = %q, want metadata differs", got)
	}

	if got := benchmarkMetadataWarning(results{}, same); !strings.Contains(got, "metadata missing") {
		t.Fatalf("missing warning = %q, want metadata missing", got)
	}
}

func TestV16BaselineCoversTrackedMetrics(t *testing.T) {
	body, err := os.ReadFile("../baselines/v1.6.0.json")
	if err != nil {
		t.Fatalf("read v1.6.0 baseline: %v", err)
	}
	var baseline results
	if err := json.Unmarshal(body, &baseline); err != nil {
		t.Fatalf("parse v1.6.0 baseline: %v", err)
	}
	for _, m := range trackedMetrics {
		raw, ok := baseline.Scenarios[m.scenario]
		if !ok {
			t.Fatalf("v1.6.0 baseline missing scenario %s", m.scenario)
		}
		if _, ok := extractField(raw, m.field); !ok {
			t.Fatalf("v1.6.0 baseline missing metric %s.%s", m.scenario, m.field)
		}
	}
}
