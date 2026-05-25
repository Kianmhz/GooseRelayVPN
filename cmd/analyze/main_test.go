package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestAnalyzeLogFilesDetectsActionableSignals(t *testing.T) {
	dir := t.TempDir()
	clientLog := filepath.Join(dir, "client.log")
	serverLog := filepath.Join(dir, "server.log")
	if err := os.WriteFile(clientLog, []byte(`
12:00:00 CARRIER WARN relay returned non-batch payload via AKfycb...Quota: Apps Script quota exhausted (20k requests/day limit)
12:00:01 CARRIER WARN relay request failed via AKfycb...Local: Post "https://script.google.com": net/http: TLS handshake timeout
12:00:02 CARRIER WARN relay returned empty/204 response via AKfycb...BadKey (likely tunnel_key/protocol mismatch)
12:00:03 CARRIER WARN relay response was invalid via AKfycb...Decode: cipher: message authentication failed
12:00:04 CARRIER INFO endpoint AKfycb...Local ok=5 fail=3 today=120 reasons={local_offline=2 non_batch=1}
12:00:05 [timing] poll rtt=2300ms tx_frames=0 rx_frames=0 resp_bytes=80 via AKfycb...SlowGoogle
12:00:06 [stats_json] {"latency":{"queue_wait":{"p95_ms":6200}}}
`), 0o644); err != nil {
		t.Fatalf("write client log: %v", err)
	}
	if err := os.WriteFile(serverLog, []byte(`
16:00:00 [timing] abcd first_read=8500ms after_dial target=openai.com:443
16:00:01 [stats_json] {"latency":{"queue_wait":{"p95_ms":7200}}}
`), 0o644); err != nil {
		t.Fatalf("write server log: %v", err)
	}

	report, err := analyzeLogFiles([]string{clientLog, serverLog})
	if err != nil {
		t.Fatalf("analyzeLogFiles: %v", err)
	}
	text := renderReport(report)
	for _, want := range []string{
		"quota: yes",
		"local network outage: yes",
		"bad deployment/key/protocol: yes",
		"google/fronting slow: yes",
		"upstream/warp slow: yes",
		"queue wait high: yes",
		"AKfycb...Quota",
		"AKfycb...BadKey",
		"local_offline=2",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered report missing %q:\n%s", want, text)
		}
	}
}

func TestReadLogTextAcceptsUTF16LE(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-utf16.log")
	raw := []uint16{0xfeff}
	raw = append(raw, utf16.Encode([]rune("quota exhausted\n"))...)
	data := make([]byte, 0, len(raw)*2)
	for _, v := range raw {
		data = append(data, byte(v), byte(v>>8))
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write utf16 log: %v", err)
	}

	text, err := readLogText(path)
	if err != nil {
		t.Fatalf("readLogText: %v", err)
	}
	if !strings.Contains(text, "quota exhausted") {
		t.Fatalf("decoded text = %q, want quota marker", text)
	}
}

func TestReadLogTextDetectsUTF16LEWithoutBOM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client-utf16-no-bom.log")
	raw := utf16.Encode([]rune("local network offline\n"))
	data := make([]byte, 0, len(raw)*2)
	for _, v := range raw {
		data = append(data, byte(v), byte(v>>8))
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write utf16 log: %v", err)
	}

	text, err := readLogText(path)
	if err != nil {
		t.Fatalf("readLogText: %v", err)
	}
	if !strings.Contains(text, "local network offline") {
		t.Fatalf("decoded text = %q, want local outage marker", text)
	}
}

func TestAnalyzeLineClassifiesMixedFailureReasons(t *testing.T) {
	report := newAnalysisReport(nil)
	analyzeLine(&report, "12:00:00 CARRIER INFO endpoint AKfycb...Mix ok=0 fail=6 today=10 reasons={local_offline=2 quota=1 rate_limit=1 empty_204=1 decode_error=1}")

	if !report.LocalNetworkOutage {
		t.Fatal("LocalNetworkOutage = false, want true from local_offline reason")
	}
	if !report.Quota {
		t.Fatal("Quota = false, want true from quota reason")
	}
	if !report.RateLimit {
		t.Fatal("RateLimit = false, want true from rate_limit reason")
	}
	if !report.BadDeploymentOrKey {
		t.Fatal("BadDeploymentOrKey = false, want true from empty_204/decode_error reasons")
	}
	if report.FailureReasons["quota"] != 1 {
		t.Fatalf("quota failure count = %d, want 1", report.FailureReasons["quota"])
	}
	for _, signal := range []string{"quota", "rate_limit", "local_offline", "bad_deployment_or_key"} {
		if _, ok := report.DeploymentsBySignal[signal]["AKfycb...Mix"]; !ok {
			t.Fatalf("deployment attribution for %s missing: %#v", signal, report.DeploymentsBySignal)
		}
	}
}

func TestAnalyzeLineClassifiesStructuredEndpointItems(t *testing.T) {
	report := newAnalysisReport(nil)
	analyzeLine(&report, `12:00:00 STATS_JSON INFO {"endpoints":{"detail":"AKfycb...first ok=5 fail=0 today=5","healthy":1,"total":2,"items":[{"label":"AKfycb...first","ok":5,"fail":0,"today":5},{"label":"AKfycb...second","ok":0,"fail":3,"today":3,"reasons":{"quota":2,"rate_limit":1}}]}}`)

	if !report.Quota {
		t.Fatal("Quota = false, want true from structured endpoint item")
	}
	if !report.RateLimit {
		t.Fatal("RateLimit = false, want true from structured endpoint item")
	}
	if report.FailureReasons["quota"] != 2 {
		t.Fatalf("quota failure count = %d, want 2", report.FailureReasons["quota"])
	}
	if _, ok := report.DeploymentsBySignal["quota"]["AKfycb...second"]; !ok {
		t.Fatalf("quota deployment attribution missing: %#v", report.DeploymentsBySignal)
	}
}

func TestAnalyzeQuotaThenNonBatchDoesNotBlameDeployment(t *testing.T) {
	report := newAnalysisReport(nil)
	analyzeLine(&report, `20:30:51 CARRIER INFO endpoint AKfycb...PLiLZg account="shaun" quota exhausted until approx 2026-05-24T00:00:00-08:00; rotating away`)
	analyzeLine(&report, `20:30:51 CARRIER INFO relay returned non-batch payload via AKfycb...PLiLZg (attempt 1/4); retrying alternate endpoint`)

	if !report.Quota {
		t.Fatal("Quota = false, want true from quota line")
	}
	if report.BadDeploymentOrKey {
		t.Fatalf("BadDeploymentOrKey = true for quota-caused non-batch; deployments=%#v", report.DeploymentsBySignal)
	}
}

func TestAnalyzeLineDoesNotDoubleCountStructuredAndLegacyReasons(t *testing.T) {
	report := newAnalysisReport(nil)
	analyzeLine(&report, `01:20:01 STATS_JSON INFO {"endpoints":{"detail":"AKfycb...one ok=228 fail=8 today=237 reasons={non_batch=4 http_error=4}","healthy":1,"total":1,"items":[{"label":"AKfycb...one","ok":228,"fail":8,"today":237,"reasons":{"non_batch":4,"http_error":4}}]}}`)

	if got := report.FailureReasons["non_batch"]; got != 4 {
		t.Fatalf("non_batch count = %d, want 4 without double-counting detail+items", got)
	}
	if got := report.FailureReasons["http_error"]; got != 4 {
		t.Fatalf("http_error count = %d, want 4 without double-counting detail+items", got)
	}
}

func TestAnalyzeLineTreatsHumanEndpointReasonsAsCumulative(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, `12:00:00 CARRIER INFO endpoint AKfycb...one ok=10 fail=3 today=13 reasons={http_error=1 read_error=2}`)
	analyzeLine(&report, `12:01:00 CARRIER INFO endpoint AKfycb...one ok=20 fail=3 today=23 reasons={http_error=1 read_error=2}`)
	analyzeLine(&report, `12:02:00 CARRIER INFO endpoint AKfycb...one ok=30 fail=4 today=34 reasons={http_error=2 read_error=2}`)

	if got := report.FailureReasons["http_error"]; got != 2 {
		t.Fatalf("http_error count = %d, want latest cumulative value 2", got)
	}
	if got := report.FailureReasons["read_error"]; got != 2 {
		t.Fatalf("read_error count = %d, want latest cumulative value 2", got)
	}
}

func TestAnalyzeLineAttributesHumanEndpointReasonsPerEndpoint(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, `12:00:00 [stats] endpoints: AKfycb...good@acct-a ok=10 fail=1 today=11 reasons={read_error=1} | AKfycb...quota@acct-b ok=2 fail=5 today=7 reasons={quota=5}`)

	if got := report.FailureReasons["read_error"]; got != 1 {
		t.Fatalf("read_error = %d, want 1", got)
	}
	if got := report.FailureReasons["quota"]; got != 5 {
		t.Fatalf("quota = %d, want 5", got)
	}
	if _, ok := report.DeploymentsBySignal["quota"]["AKfycb...quota@acct-b"]; !ok {
		t.Fatalf("quota deployment attribution missing: %#v", report.DeploymentsBySignal)
	}
	if _, ok := report.DeploymentsBySignal["relay_read_error"]["AKfycb...good@acct-a"]; !ok {
		t.Fatalf("read_error deployment attribution missing: %#v", report.DeploymentsBySignal)
	}
}

func TestAnalyzeLineDoesNotFlagHealthyTunnelKeyStartup(t *testing.T) {
	report := newAnalysisReport(nil)
	analyzeLine(&report, "12:00:00 SERVER INFO [exit] tunnel_key loaded (32 bytes)")

	if report.BadDeploymentOrKey {
		t.Fatal("healthy tunnel_key startup log was classified as bad deployment/key")
	}
}

func TestAnalyzeLineClassifiesReceiveAborts(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, "20:17:09 CARRIER INFO session b269400f target=storage.googleapis.com:443 receive aborted: rx_reorder_overflow")
	analyzeLine(&report, "20:18:09 [stats] receive_abort={rx_inbox_timeout=2 rx_reorder_overflow=1 other=1}")
	analyzeLine(&report, `20:19:09 [stats_json] {"receive_abort":{"rx_inbox_timeout":3,"rx_reorder_overflow":4}}`)

	if !report.ReceiveAbort {
		t.Fatal("ReceiveAbort = false, want true")
	}
	if report.ReceiveAbortReasons["rx_reorder_overflow"] != 6 {
		t.Fatalf("rx_reorder_overflow count = %d, want 6", report.ReceiveAbortReasons["rx_reorder_overflow"])
	}
	if report.ReceiveAbortReasons["rx_inbox_timeout"] != 5 {
		t.Fatalf("rx_inbox_timeout count = %d, want 5", report.ReceiveAbortReasons["rx_inbox_timeout"])
	}

	text := renderReport(report)
	for _, want := range []string{
		"receive aborts: yes",
		"rx_inbox_timeout=5",
		"rx_reorder_overflow=6",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered report missing %q:\n%s", want, text)
		}
	}
}

func TestAnalyzeLineTreatsReceiveAbortStatsAsCumulative(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, "20:18:09 [stats] receive_abort={rx_inbox_timeout=2 rx_reorder_overflow=1}")
	analyzeLine(&report, "20:19:09 [stats] receive_abort={rx_inbox_timeout=2 rx_reorder_overflow=1}")
	analyzeLine(&report, "20:20:09 [stats] receive_abort={rx_inbox_timeout=3 rx_reorder_overflow=1}")

	if got := report.ReceiveAbortReasons["rx_inbox_timeout"]; got != 3 {
		t.Fatalf("rx_inbox_timeout count = %d, want latest cumulative value 3", got)
	}
	if got := report.ReceiveAbortReasons["rx_reorder_overflow"]; got != 1 {
		t.Fatalf("rx_reorder_overflow count = %d, want latest cumulative value 1", got)
	}
}

func TestAnalyzeLineClassifiesDownstreamReplay(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, "20:20:09 [stats] replay enabled=true ack_received=9 frames=3 bytes=512B pruned=2 dropped_sessions=1 buffer=256B")
	analyzeLine(&report, `20:21:09 [stats_json] {"downstream_replay":{"enabled":true,"replay_frames":4,"replay_bytes":1024,"replay_pruned":3,"dropped_sessions":2,"buffer_bytes":512,"ack_only_posts":12,"ack_only_frames":14}}`)
	analyzeLine(&report, "20:22:09 [stats] replay active=true ack_sent=11")

	if !report.ReplayEnabled {
		t.Fatal("ReplayEnabled = false, want true")
	}
	if !report.ReplayActive {
		t.Fatal("ReplayActive = false, want true")
	}
	if !report.ReplayHappened {
		t.Fatal("ReplayHappened = false, want true")
	}
	if !report.ReplayDroppedSessions {
		t.Fatal("ReplayDroppedSessions = false, want true")
	}
	if report.ReplayCounters["frames"] != 3 || report.ReplayCounters["replay_frames"] != 4 {
		t.Fatalf("replay frame counters = %#v", report.ReplayCounters)
	}
	if report.ReplayCounters["bytes"] != 512 {
		t.Fatalf("bytes counter = %d, want 512", report.ReplayCounters["bytes"])
	}
	if report.ReplayGauges["buffer"] != 256 || report.ReplayGauges["buffer_bytes"] != 512 {
		t.Fatalf("replay gauges = %#v", report.ReplayGauges)
	}
	if _, ok := report.ReplayCounters["buffer"]; ok {
		t.Fatalf("buffer gauge was recorded as counter: %#v", report.ReplayCounters)
	}
	if report.ReplayCounters["ack_only_posts"] != 12 || report.ReplayCounters["ack_only_frames"] != 14 {
		t.Fatalf("ack-only replay counters = %#v", report.ReplayCounters)
	}

	text := renderReport(report)
	for _, want := range []string{
		"downstream replay enabled: yes",
		"downstream replay active: yes",
		"downstream replay happened: yes",
		"dropped_sessions=3",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered report missing %q:\n%s", want, text)
		}
	}
}

func TestAnalyzeRecommendationsFlagACKOnlyPostChurn(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, `20:21:09 [stats_json] {"downstream_replay":{"active":true,"ack_sent":500,"ack_only_posts":120,"ack_only_frames":145}}`)

	text := renderReport(report)
	for _, want := range []string{
		"ack_only_posts=120",
		"ACK-only POST",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered report missing %q:\n%s", want, text)
		}
	}
}

func TestAnalyzeRecommendationsSuggestBackupEndpointForSingleEndpointFailures(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, `01:20:01 STATS_JSON INFO {"endpoints":{"detail":"AKfycb...one ok=228 fail=8 today=237 reasons={non_batch=4 http_error=4}","healthy":1,"total":1}}`)

	text := renderReport(report)
	for _, want := range []string{
		"single relay endpoint",
		"backup deployment",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered report missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "no strong failure signal") {
		t.Fatalf("rendered report included contradictory no-signal recommendation:\n%s", text)
	}
}

func TestAnalyzeLineParsesHumanReplayByteUnits(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, "20:20:09 [stats] replay enabled=true frames=1 bytes=1.5KB buffer=2.0MB")

	if got, want := report.ReplayCounters["bytes"], uint64(1536); got != want {
		t.Fatalf("bytes counter = %d, want %d", got, want)
	}
	if got, want := report.ReplayGauges["buffer"], uint64(2*1024*1024); got != want {
		t.Fatalf("buffer gauge = %d, want %d", got, want)
	}
}

func TestAnalyzeReplayBufferGaugeIsNotAccumulated(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, "20:20:09 [stats] replay enabled=true buffer=2.0MB")
	analyzeLine(&report, "20:21:09 [stats] replay enabled=true buffer=1.0MB")
	analyzeLine(&report, "20:22:09 [stats] replay enabled=true buffer=1.5MB")

	if got, want := report.ReplayGauges["buffer"], uint64(2*1024*1024); got != want {
		t.Fatalf("buffer gauge = %d, want max observed %d", got, want)
	}
	if _, ok := report.ReplayCounters["buffer"]; ok {
		t.Fatalf("buffer gauge was accumulated as counter: %#v", report.ReplayCounters)
	}
}

func TestAnalyzeRecommendationsSuggestReplayWhenOffAndSequenceGapsAppear(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, "20:17:09 CARRIER INFO session b269400f target=storage.googleapis.com:443 receive aborted: rx_reorder_overflow")
	analyzeLine(&report, "20:18:09 CARRIER WARN failed to read relay response: http2: client connection lost")

	text := renderReport(report)
	for _, want := range []string{
		"enable downstream replay",
		"fronting_http_version: \"h1\"",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered report missing %q:\n%s", want, text)
		}
	}
}

func TestAnalyzeRecommendationsSuggestIdlePollSaverWhenIdleBurnIsHigh(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, "12:00:00 [stats] active=0 sessions=0/0 frames=0/0 bytes=0B/0B polls(ok=120 fail=0 useful=0 empty=118 idle=118 suppress=0 busy=0) rst=0 endpoints=1/1")

	text := renderReport(report)
	if !strings.Contains(text, "idle_poll_mode") {
		t.Fatalf("rendered report missing idle_poll_mode recommendation:\n%s", text)
	}
}

func TestAnalyzeReaderProcessesOnlyNewBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.log")
	if err := os.WriteFile(path, []byte("12:00:00 quota exhausted\n"), 0o644); err != nil {
		t.Fatalf("write initial log: %v", err)
	}

	state := newFollowState([]string{path})
	first, err := state.Poll()
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if !first.Quota || first.Lines != 1 {
		t.Fatalf("first report = %#v, want one quota line", first)
	}

	second, err := state.Poll()
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if second.Lines != 0 || second.Quota {
		t.Fatalf("second report = %#v, want no duplicate analysis", second)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	_, err = f.WriteString("12:00:01 local network offline\n")
	_ = f.Close()
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	third, err := state.Poll()
	if err != nil {
		t.Fatalf("third poll: %v", err)
	}
	if !third.LocalNetworkOutage || third.Lines != 1 || third.Quota {
		t.Fatalf("third report = %#v, want one new local outage line only", third)
	}
}

func TestAnalyzeReaderHandlesLogTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.log")
	if err := os.WriteFile(path, []byte("12:00:00 quota exhausted\n12:00:01 rate limited\n"), 0o644); err != nil {
		t.Fatalf("write initial log: %v", err)
	}
	state := newFollowState([]string{path})
	if _, err := state.Poll(); err != nil {
		t.Fatalf("initial poll: %v", err)
	}

	if err := os.WriteFile(path, []byte("12:01:00 tunnel_key/protocol mismatch\n"), 0o644); err != nil {
		t.Fatalf("truncate log: %v", err)
	}
	report, err := state.Poll()
	if err != nil {
		t.Fatalf("post-truncate poll: %v", err)
	}
	if !report.BadDeploymentOrKey || report.Lines != 1 || report.Quota || report.RateLimit {
		t.Fatalf("post-truncate report = %#v, want only new truncated content", report)
	}
}

func TestAnalyzeFollowPreservesPartialLinesBetweenPolls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.log")
	if err := os.WriteFile(path, []byte("12:00:00 quo"), 0o644); err != nil {
		t.Fatalf("write partial log: %v", err)
	}

	state := newFollowState([]string{path})
	first, err := state.Poll()
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if first.Lines != 0 || first.Quota {
		t.Fatalf("first report = %#v, want no analysis until line is complete", first)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	_, err = f.WriteString("ta exhausted\n")
	_ = f.Close()
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	second, err := state.Poll()
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if second.Lines != 1 || !second.Quota {
		t.Fatalf("second report = %#v, want one completed quota line", second)
	}
}

func TestAnalyzeFollowKeepsCumulativeCounterStateAcrossPolls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.log")
	firstStats := `12:00:00 STATS_JSON INFO {"component":"carrier","payload":{"compression":{"attempted":2,"raw":10}},"downstream_replay":{"active":true,"ack_sent":5},"endpoints":{"items":[{"label":"ep1","account":"acct","reasons":{"read_error":1}}],"healthy":1,"total":1}}` + "\n"
	if err := os.WriteFile(path, []byte(firstStats), 0o644); err != nil {
		t.Fatalf("write first stats: %v", err)
	}

	state := newFollowState([]string{path})
	first, err := state.Poll()
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if first.CompressionCounters["attempted"] != 2 || first.ReplayCounters["ack_sent"] != 5 || first.FailureReasons["read_error"] != 1 {
		t.Fatalf("first counters = compression %#v replay %#v failures %#v", first.CompressionCounters, first.ReplayCounters, first.FailureReasons)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open append: %v", err)
	}
	secondStats := `12:00:01 STATS_JSON INFO {"component":"carrier","payload":{"compression":{"attempted":3,"raw":14}},"downstream_replay":{"active":true,"ack_sent":8},"endpoints":{"items":[{"label":"ep1","account":"acct","reasons":{"read_error":4}}],"healthy":1,"total":1}}` + "\n"
	_, err = f.WriteString(secondStats)
	_ = f.Close()
	if err != nil {
		t.Fatalf("append stats: %v", err)
	}

	second, err := state.Poll()
	if err != nil {
		t.Fatalf("second poll: %v", err)
	}
	if got := second.CompressionCounters["attempted"]; got != 1 {
		t.Fatalf("second compression attempted = %d, want delta 1", got)
	}
	if got := second.CompressionCounters["raw"]; got != 4 {
		t.Fatalf("second compression raw = %d, want delta 4", got)
	}
	if got := second.ReplayCounters["ack_sent"]; got != 3 {
		t.Fatalf("second replay ack_sent = %d, want delta 3", got)
	}
	if got := second.FailureReasons["read_error"]; got != 3 {
		t.Fatalf("second read_error = %d, want delta 3", got)
	}
}

func TestAnalyzeFollowKeepsCumulativeCountersPerFile(t *testing.T) {
	dir := t.TempDir()
	clientLog := filepath.Join(dir, "client.log")
	serverLog := filepath.Join(dir, "server.log")
	line := `12:00:00 STATS_JSON INFO {"component":"carrier","payload":{"compression":{"attempted":2}}}` + "\n"
	if err := os.WriteFile(clientLog, []byte(line), 0o644); err != nil {
		t.Fatalf("write client log: %v", err)
	}
	if err := os.WriteFile(serverLog, []byte(line), 0o644); err != nil {
		t.Fatalf("write server log: %v", err)
	}

	state := newFollowState([]string{clientLog, serverLog})
	report, err := state.Poll()
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if got := report.CompressionCounters["attempted"]; got != 4 {
		t.Fatalf("combined attempted = %d, want both files counted independently", got)
	}
}

func TestAnalyzeFollowActionableSignalIgnoresHealthySingleEndpoint(t *testing.T) {
	healthy := analysisReport{SingleRelayEndpoint: true}
	if hasActionableSignal(healthy) {
		t.Fatalf("healthy single-endpoint report should not wake follow mode")
	}

	failing := analysisReport{
		SingleRelayEndpoint: true,
		FailureReasons:      map[string]uint64{"http_error": 1},
	}
	if !hasActionableSignal(failing) {
		t.Fatalf("single-endpoint relay failure should wake follow mode")
	}

	targetChurn := newAnalysisReport(nil)
	targetChurn.recordTargetFailure("127.0.0.1:10808", false)
	if !hasActionableSignal(targetChurn) {
		t.Fatalf("target failure report should wake follow mode")
	}
}

func TestAnalyzeReportRendersFieldDashboard(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, `12:00:00 STATS_JSON INFO {"ts":"2026-05-24T00:00:00+03:30","endpoints":{"healthy":1,"total":2,"items":[{"label":"AKfycb...good","account":"shaun","ok":20,"fail":0,"today":100},{"label":"AKfycb...quota","account":"backup","ok":1,"fail":7,"today":19000,"quota_reset_sec":3600,"reasons":{"quota":7}}]}}`)
	analyzeLine(&report, `12:00:01 [timing] poll rtt=2400ms tx_frames=4 rx_frames=13 resp_bytes=2812345 via AKfycb...good`)
	analyzeLine(&report, `12:00:02 [timing] abcd ttfb=9100ms target=video.example:443`)
	analyzeLine(&report, `12:00:03 [timing] ef01 first_read=8500ms after_dial target=proxy.example:443`)
	analyzeLine(&report, `12:00:04 [exit] dial 127.0.0.1:10808: dial tcp 127.0.0.1:10808: connectex: No connection could be made`)
	analyzeLine(&report, `12:00:05 [exit] dial suppressed for 127.0.0.1:10808 (recent failure backoff); sending RST`)

	if !report.Quota {
		t.Fatal("quota reset countdown should mark report quota=true")
	}

	text := renderReport(report)
	for _, want := range []string{
		"endpoint timeline:",
		"2026-05-24T00:00:00+03:30 healthy=1/2",
		"quota reset countdowns:",
		"AKfycb...quota account=backup quota_reset=3600s",
		"healthy accounts over time:",
		"backup healthy=0/1",
		"shaun healthy=1/1",
		"top failed targets:",
		"127.0.0.1:10808 fail=1 suppressed=1",
		"top slow targets:",
		"video.example:443 ttfb_max=9100ms",
		"proxy.example:443 first_read_max=8500ms",
		"largest response batches:",
		"AKfycb...good resp=2812345B rtt=2400ms rx=13",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered report missing %q:\n%s", want, text)
		}
	}
}

func TestAnalyzeEndpointTimelineCollapsesRepeats(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, `12:00:00 STATS_JSON INFO {"ts":"2026-05-24T00:00:00Z","endpoints":{"healthy":2,"total":5}}`)
	analyzeLine(&report, `12:01:00 STATS_JSON INFO {"ts":"2026-05-24T00:01:00Z","endpoints":{"healthy":2,"total":5}}`)
	analyzeLine(&report, `12:02:00 STATS_JSON INFO {"ts":"2026-05-24T00:02:00Z","endpoints":{"healthy":1,"total":5}}`)

	if got := len(report.EndpointTimeline); got != 2 {
		t.Fatalf("EndpointTimeline len = %d, want 2", got)
	}
	if report.EndpointTimeline[0].TS != "2026-05-24T00:00:00Z" {
		t.Fatalf("first timeline timestamp = %q", report.EndpointTimeline[0].TS)
	}
	if report.EndpointTimeline[1].Healthy != 1 || report.EndpointTimeline[1].Total != 5 {
		t.Fatalf("second timeline item = %#v, want healthy=1 total=5", report.EndpointTimeline[1])
	}
}

func TestAnalyzeReportRendersCompressionSummary(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, `12:00:00 STATS_JSON INFO {"payload":{"compression":{"attempted":12,"used":5,"skipped":7,"raw":7,"zstd":5,"raw_bytes":10000,"body_bytes":7000,"wire_bytes":9400,"saved_bytes":3000,"lost_bytes":40}}}`)
	analyzeLine(&report, `12:01:00 [stats] compression modes(raw=1 zstd=2) attempted=3 used=2 skipped=1 raw_bytes=1.0KB body_bytes=512B wire_bytes=700B saved_bytes=256B lost_bytes=10B`)

	text := renderReport(report)
	for _, want := range []string{
		"compression:",
		"attempted=15",
		"used=7",
		"skipped=8",
		"raw=8",
		"zstd=7",
		"raw_bytes=11024",
		"body_bytes=7512",
		"wire_bytes=10100",
		"saved_bytes=3256",
		"lost_bytes=50",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered report missing %q:\n%s", want, text)
		}
	}
}

func TestAnalyzeStructuredStatsTreatsCumulativeCountersAsDeltas(t *testing.T) {
	report := newAnalysisReport(nil)

	analyzeLine(&report, `12:00:00 STATS_JSON INFO {"component":"carrier","payload":{"compression":{"attempted":2,"raw":10,"raw_bytes":1000}},"downstream_replay":{"active":true,"ack_sent":5,"replay_frames":2},"endpoints":{"items":[{"label":"ep1","account":"acct","reasons":{"read_error":1}}],"healthy":1,"total":1}}`)
	analyzeLine(&report, `12:01:00 STATS_JSON INFO {"component":"carrier","payload":{"compression":{"attempted":3,"raw":14,"raw_bytes":1500}},"downstream_replay":{"active":true,"ack_sent":8,"replay_frames":3},"endpoints":{"items":[{"label":"ep1","account":"acct","reasons":{"read_error":1}}],"healthy":1,"total":1}}`)

	if got := report.CompressionCounters["attempted"]; got != 3 {
		t.Fatalf("compression attempted = %d, want last cumulative value 3", got)
	}
	if got := report.CompressionCounters["raw"]; got != 14 {
		t.Fatalf("compression raw = %d, want last cumulative value 14", got)
	}
	if got := report.CompressionCounters["raw_bytes"]; got != 1500 {
		t.Fatalf("compression raw_bytes = %d, want last cumulative value 1500", got)
	}
	if got := report.ReplayCounters["ack_sent"]; got != 8 {
		t.Fatalf("replay ack_sent = %d, want last cumulative value 8", got)
	}
	if got := report.ReplayCounters["replay_frames"]; got != 3 {
		t.Fatalf("replay_frames = %d, want last cumulative value 3", got)
	}
	if got := report.FailureReasons["read_error"]; got != 1 {
		t.Fatalf("read_error = %d, want last cumulative value 1", got)
	}
}
