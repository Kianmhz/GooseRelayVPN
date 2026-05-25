package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	slowGoogleRTTMS       = 1500
	slowUpstreamFirstRead = 5000
	highQueueWaitMS       = 5000
	highACKOnlyPosts      = 100
)

type analysisReport struct {
	Files                  []string
	Lines                  int
	Quota                  bool
	RateLimit              bool
	LocalNetworkOutage     bool
	BadDeploymentOrKey     bool
	GoogleFrontingSlow     bool
	UpstreamOrWARPSlow     bool
	QueueWaitHigh          bool
	ReceiveAbort           bool
	RelayReadError         bool
	HTTP2FrontingIssue     bool
	IdleQuotaBurn          bool
	ACKOnlyPostChurn       bool
	SingleRelayEndpoint    bool
	ReplayEnabled          bool
	ReplayActive           bool
	ReplayHappened         bool
	ReplayDroppedSessions  bool
	MaxGoogleRTTMS         int
	MaxUpstreamFirstReadMS int
	MaxQueueWaitP95MS      int
	DeploymentsBySignal    map[string]map[string]struct{}
	FailureReasons         map[string]uint64
	ReceiveAbortReasons    map[string]uint64
	ReplayCounters         map[string]uint64
	ReplayGauges           map[string]uint64
	CompressionCounters    map[string]uint64
	cumulativeFailures     map[string]uint64
	cumulativeReceiveAbort map[string]uint64
	cumulativeReplay       map[string]uint64
	cumulativeCompression  map[string]uint64
	EndpointTimeline       []endpointTimelineEntry
	QuotaCountdowns        map[string]quotaCountdown
	AccountHealth          map[string]accountHealth
	TargetFailures         map[string]*targetFailureSummary
	SlowTargets            map[string]*slowTargetSummary
	ResponseBatches        []responseBatchSummary
}

func newAnalysisReport(paths []string) analysisReport {
	return analysisReport{
		Files:                  append([]string(nil), paths...),
		DeploymentsBySignal:    map[string]map[string]struct{}{},
		FailureReasons:         map[string]uint64{},
		ReceiveAbortReasons:    map[string]uint64{},
		ReplayCounters:         map[string]uint64{},
		ReplayGauges:           map[string]uint64{},
		CompressionCounters:    map[string]uint64{},
		cumulativeFailures:     map[string]uint64{},
		cumulativeReceiveAbort: map[string]uint64{},
		cumulativeReplay:       map[string]uint64{},
		cumulativeCompression:  map[string]uint64{},
		QuotaCountdowns:        map[string]quotaCountdown{},
		AccountHealth:          map[string]accountHealth{},
		TargetFailures:         map[string]*targetFailureSummary{},
		SlowTargets:            map[string]*slowTargetSummary{},
	}
}

type endpointTimelineEntry struct {
	TS      string
	Healthy uint64
	Total   uint64
}

func (r *analysisReport) recordEndpointHealth(ts string, healthy, total uint64) {
	if len(r.EndpointTimeline) > 0 {
		last := r.EndpointTimeline[len(r.EndpointTimeline)-1]
		if last.Healthy == healthy && last.Total == total {
			return
		}
	}
	r.EndpointTimeline = append(r.EndpointTimeline, endpointTimelineEntry{
		TS:      ts,
		Healthy: healthy,
		Total:   total,
	})
}

type quotaCountdown struct {
	Account string
	Seconds uint64
}

type accountHealth struct {
	Healthy uint64
	Total   uint64
}

type targetFailureSummary struct {
	Fail       uint64
	Suppressed uint64
}

type slowTargetSummary struct {
	TTFBMaxMS      int
	FirstReadMaxMS int
}

type responseBatchSummary struct {
	Endpoint  string
	RTTMS     int
	TXFrames  int
	RXFrames  int
	RespBytes int
}

func main() {
	log.SetFlags(0)
	follow := flag.Bool("follow", false, "keep watching appended log lines and print a fresh report when new signals appear")
	interval := flag.Duration("interval", 2*time.Second, "poll interval for --follow")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: goose-analyze [--follow] <client.log> [server.log ...]\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *follow {
		if err := followLogFiles(flag.Args(), *interval); err != nil {
			log.Fatal(err)
		}
		return
	}
	report, err := analyzeLogFiles(flag.Args())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(renderReport(report))
}

func analyzeLogFiles(paths []string) (analysisReport, error) {
	report := newAnalysisReport(paths)
	for _, path := range paths {
		text, err := readLogText(path)
		if err != nil {
			return report, err
		}
		sourceHint := filepath.Base(path)
		for _, line := range strings.Split(text, "\n") {
			report.Lines++
			analyzeLineFrom(&report, line, sourceHint)
		}
	}
	return report, nil
}

type followState struct {
	paths                  []string
	offsets                map[string]int64
	partials               map[string]string
	cumulativeFailures     map[string]uint64
	cumulativeReceiveAbort map[string]uint64
	cumulativeReplay       map[string]uint64
	cumulativeCompression  map[string]uint64
}

func newFollowState(paths []string) *followState {
	return &followState{
		paths:                  append([]string(nil), paths...),
		offsets:                map[string]int64{},
		partials:               map[string]string{},
		cumulativeFailures:     map[string]uint64{},
		cumulativeReceiveAbort: map[string]uint64{},
		cumulativeReplay:       map[string]uint64{},
		cumulativeCompression:  map[string]uint64{},
	}
}

func (s *followState) Poll() (analysisReport, error) {
	report := newAnalysisReport(s.paths)
	report.cumulativeFailures = s.cumulativeFailures
	report.cumulativeReceiveAbort = s.cumulativeReceiveAbort
	report.cumulativeReplay = s.cumulativeReplay
	report.cumulativeCompression = s.cumulativeCompression
	for _, path := range s.paths {
		sourceHint := filepath.Base(path)
		info, err := os.Stat(path)
		if err != nil {
			return report, err
		}
		offset := s.offsets[path]
		if info.Size() < offset {
			offset = 0
			s.partials[path] = ""
		}
		f, err := os.Open(path)
		if err != nil {
			return report, err
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			_ = f.Close()
			return report, err
		}
		data, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return report, err
		}
		s.offsets[path] = offset + int64(len(data))
		text := decodeLogBytes(data)
		if text == "" {
			continue
		}
		text = s.partials[path] + text
		if !strings.HasSuffix(text, "\n") {
			parts := strings.Split(text, "\n")
			s.partials[path] = parts[len(parts)-1]
			text = strings.Join(parts[:len(parts)-1], "\n")
		} else {
			s.partials[path] = ""
		}
		if text == "" {
			continue
		}
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimRight(line, "\r")
			if strings.TrimSpace(line) == "" {
				continue
			}
			report.Lines++
			analyzeLineFrom(&report, line, sourceHint)
		}
	}
	return report, nil
}

func followLogFiles(paths []string, interval time.Duration) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	state := newFollowState(paths)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		report, err := state.Poll()
		if err != nil {
			return err
		}
		if report.Lines > 0 && hasActionableSignal(report) {
			fmt.Print(renderReport(report))
		}
		<-ticker.C
	}
}

func hasActionableSignal(report analysisReport) bool {
	return report.Quota || report.RateLimit || report.LocalNetworkOutage || report.BadDeploymentOrKey ||
		report.GoogleFrontingSlow || report.UpstreamOrWARPSlow || report.QueueWaitHigh || report.ReceiveAbort ||
		report.RelayReadError || report.HTTP2FrontingIssue || report.IdleQuotaBurn || report.ACKOnlyPostChurn ||
		hasSingleEndpointRelayFailure(report) || report.ReplayHappened || report.ReplayDroppedSessions ||
		len(report.TargetFailures) > 0
}

var (
	timingPollRTTRe        = regexp.MustCompile(`\bpoll rtt=(\d+)ms\b`)
	timingPollBatchRe      = regexp.MustCompile(`\bpoll rtt=(\d+)ms tx_frames=(\d+) rx_frames=(\d+) resp_bytes=(\d+) via ([^\s:;)]+)`)
	timingTTFBTargetRe     = regexp.MustCompile(`\bttfb=(\d+)ms target=([^\s]+)`)
	firstReadTargetRe      = regexp.MustCompile(`\bfirst_read=(\d+)ms\b.*\btarget=([^\s]+)`)
	firstReadRe            = regexp.MustCompile(`\bfirst_read=(\d+)ms\b`)
	exitDialFailureRe      = regexp.MustCompile(`\] dial (.+?): `)
	exitDialSuppressedRe   = regexp.MustCompile(`dial suppressed for ([^\s]+)`)
	queueWaitP95Re         = regexp.MustCompile(`"queue_wait"\s*:\s*\{[^}]*"(?:p95|p95_ms)"\s*:\s*(\d+)`)
	humanQueueWaitP95Re    = regexp.MustCompile(`queue_wait\[[^\]]*p95=(\d+)ms`)
	humanPollsRe           = regexp.MustCompile(`polls\(ok=(\d+) fail=(\d+) useful=(\d+) empty=(\d+) idle=(\d+)`)
	endpointViaRe          = regexp.MustCompile(`\bvia\s+([^\s:;)]+)`)
	endpointStatsRe        = regexp.MustCompile(`\bendpoint\s+([^\s:;)]+)`)
	endpointFailureReasons = regexp.MustCompile(`reasons=\{([^}]*)\}`)
	receiveAbortStatsRe    = regexp.MustCompile(`receive_abort=\{([^}]*)\}`)
	receiveAbortJSONRe     = regexp.MustCompile(`"receive_abort"\s*:\s*\{([^}]*)\}`)
	receiveAbortedRe       = regexp.MustCompile(`receive aborted:\s*([a-z0-9_]+)`)
	replayStatsRe          = regexp.MustCompile(`replay\s+(.*)`)
	replayJSONRe           = regexp.MustCompile(`"downstream_replay"\s*:\s*\{([^}]*)\}`)
	endpointTotalJSONRe    = regexp.MustCompile(`"total"\s*:\s*(\d+)`)
	humanEndpointTotalRe   = regexp.MustCompile(`\bendpoints=\d+/(\d+)`)
	reasonCountRe          = regexp.MustCompile(`([a-z0-9_]+)=([0-9]+(?:\.[0-9]+)?(?:[kmgtKMGT]?[bB])?)`)
	jsonReasonCountRe      = regexp.MustCompile(`"([a-z0-9_]+)"\s*:\s*(\d+)`)
	compressionStatsRe     = regexp.MustCompile(`compression\s+(.*)`)
)

func analyzeLine(report *analysisReport, line string) {
	analyzeLineFrom(report, line, "")
}

func analyzeLineFrom(report *analysisReport, line, sourceHint string) {
	lower := strings.ToLower(line)
	endpoint := endpointFromLine(line)
	isStatsJSONLine := strings.Contains(lower, "stats_json")
	structuredEndpointReasons := analyzeStructuredStatsJSON(report, line, sourceHint)
	humanEndpointReasons := analyzeHumanEndpointStats(report, line, sourceHint)

	switch {
	case containsAny(lower, "quota exhausted", "service invoked too many times", "daily quota", "bandwidth quota exceeded", "reasons={quota"):
		report.Quota = true
		report.addDeployment("quota", endpoint)
	case containsAny(lower, "rate-limited", "rate limited", "http 429", "reasons={rate_limit"):
		report.RateLimit = true
		report.addDeployment("rate_limit", endpoint)
	}

	if containsAny(lower,
		"local network offline",
		"network is unreachable",
		"network is down",
		"no route to host",
		"temporary failure in name resolution",
		"no such host",
		"tls handshake timeout",
		"http2: client connection lost",
		"connected party did not properly respond",
		"connected host has failed to respond",
		"reasons={local_offline",
	) {
		report.LocalNetworkOutage = true
		report.addDeployment("local_offline", endpoint)
	}
	if strings.Contains(lower, "failed to read relay response") {
		report.RelayReadError = true
	}
	if strings.Contains(lower, "http2:") {
		report.HTTP2FrontingIssue = true
	}

	if containsAny(lower,
		"empty/204 response",
		"tunnel_key mismatch",
		"tunnel_key/protocol mismatch",
		"key mismatch",
		"protocol mismatch",
		"message authentication failed",
		"relay response was invalid",
		"decode_error",
	) {
		report.BadDeploymentOrKey = true
		report.addDeployment("bad_deployment_or_key", endpoint)
	}
	if strings.Contains(lower, "non-batch payload") &&
		!containsAny(lower, "quota", "rate-limit", "rate limited") &&
		!report.hasDeploymentSignal("quota", endpoint) {
		report.BadDeploymentOrKey = true
		report.addDeployment("bad_deployment_or_key", endpoint)
	}

	if m := timingPollRTTRe.FindStringSubmatch(line); len(m) == 2 {
		if v := atoi(m[1]); v > report.MaxGoogleRTTMS {
			report.MaxGoogleRTTMS = v
		}
		if v := atoi(m[1]); v >= slowGoogleRTTMS {
			report.GoogleFrontingSlow = true
			report.addDeployment("google_fronting_slow", endpoint)
		}
	}
	if m := timingPollBatchRe.FindStringSubmatch(line); len(m) == 6 {
		report.recordResponseBatch(responseBatchSummary{
			RTTMS:     atoi(m[1]),
			TXFrames:  atoi(m[2]),
			RXFrames:  atoi(m[3]),
			RespBytes: atoi(m[4]),
			Endpoint:  strings.Trim(m[5], ".,"),
		})
	}
	if m := firstReadRe.FindStringSubmatch(line); len(m) == 2 {
		if v := atoi(m[1]); v > report.MaxUpstreamFirstReadMS {
			report.MaxUpstreamFirstReadMS = v
		}
		if v := atoi(m[1]); v >= slowUpstreamFirstRead {
			report.UpstreamOrWARPSlow = true
		}
	}
	if m := timingTTFBTargetRe.FindStringSubmatch(line); len(m) == 3 {
		report.recordSlowTarget(m[2], atoi(m[1]), 0)
	}
	if m := firstReadTargetRe.FindStringSubmatch(line); len(m) == 3 {
		report.recordSlowTarget(m[2], 0, atoi(m[1]))
	}
	if m := exitDialFailureRe.FindStringSubmatch(line); len(m) == 2 && strings.Contains(line, "[exit] dial ") {
		report.recordTargetFailure(strings.TrimSpace(m[1]), false)
	}
	if m := exitDialSuppressedRe.FindStringSubmatch(line); len(m) == 2 {
		report.recordTargetFailure(strings.Trim(m[1], ".,;"), true)
	}
	for _, re := range []*regexp.Regexp{queueWaitP95Re, humanQueueWaitP95Re} {
		if m := re.FindStringSubmatch(line); len(m) == 2 {
			v := atoi(m[1])
			if v > report.MaxQueueWaitP95MS {
				report.MaxQueueWaitP95MS = v
			}
			if v >= highQueueWaitMS {
				report.QueueWaitHigh = true
			}
		}
	}
	if m := humanPollsRe.FindStringSubmatch(line); len(m) == 6 {
		useful := atoi(m[3])
		empty := atoi(m[4])
		idle := atoi(m[5])
		if idle >= 60 && empty >= idle/2 && useful == 0 {
			report.IdleQuotaBurn = true
		}
	}
	if m := endpointTotalJSONRe.FindStringSubmatch(line); len(m) == 2 && atoi(m[1]) == 1 {
		report.SingleRelayEndpoint = true
	}
	if m := humanEndpointTotalRe.FindStringSubmatch(line); len(m) == 2 && atoi(m[1]) == 1 {
		report.SingleRelayEndpoint = true
	}
	if !structuredEndpointReasons && !humanEndpointReasons {
		for _, m := range endpointFailureReasons.FindAllStringSubmatch(line, -1) {
			if len(m) != 2 {
				continue
			}
			addFailureReasonCounts(report, cumulativeSource(endpoint, sourceHint), endpoint, reasonCountRe.FindAllStringSubmatch(m[1], -1))
		}
	}
	if m := receiveAbortedRe.FindStringSubmatch(lower); len(m) == 2 {
		report.ReceiveAbort = true
		report.ReceiveAbortReasons[m[1]]++
	}
	if m := receiveAbortStatsRe.FindStringSubmatch(lower); len(m) == 2 {
		addReceiveAbortReasonCounts(report, cumulativeSource("human_receive_abort", sourceHint), reasonCountRe.FindAllStringSubmatch(m[1], -1))
	}
	if m := receiveAbortJSONRe.FindStringSubmatch(lower); len(m) == 2 {
		addReceiveAbortReasonCounts(report, cumulativeSource("json_receive_abort", sourceHint), jsonReasonCountRe.FindAllStringSubmatch(m[1], -1))
	}
	if m := replayStatsRe.FindStringSubmatch(lower); len(m) == 2 {
		analyzeReplayFields(report, cumulativeSource("human", sourceHint), m[1], reasonCountRe.FindAllStringSubmatch(m[1], -1))
	}
	if !isStatsJSONLine {
		if m := replayJSONRe.FindStringSubmatch(lower); len(m) == 2 {
			analyzeReplayFields(report, cumulativeSource("json", sourceHint), m[1], jsonReasonCountRe.FindAllStringSubmatch(m[1], -1))
		}
	}
	if m := compressionStatsRe.FindStringSubmatch(lower); len(m) == 2 {
		addCompressionCounters(report, cumulativeSource("human", sourceHint), reasonCountRe.FindAllStringSubmatch(m[1], -1))
	}
}

func analyzeStructuredStatsJSON(report *analysisReport, line, sourceHint string) bool {
	if !strings.Contains(strings.ToLower(line), "stats_json") {
		return false
	}
	start := strings.Index(line, "{")
	if start < 0 {
		return false
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(line[start:]), &root); err != nil {
		return false
	}
	component := jsonString(root["component"])
	if component == "" {
		component = "stats_json"
	}
	componentSource := cumulativeSource(component, sourceHint)
	analyzeStructuredCompressionJSON(report, root, componentSource)
	analyzeStructuredReplayJSON(report, root, componentSource)
	endpoints, _ := root["endpoints"].(map[string]any)
	if endpoints == nil {
		return false
	}
	healthy, healthyOK := jsonNumber(endpoints["healthy"])
	total, totalOK := jsonNumber(endpoints["total"])
	if totalOK {
		if total == 1 {
			report.SingleRelayEndpoint = true
		}
		if healthyOK {
			ts := jsonString(root["ts"])
			if ts == "" {
				ts = lineTimestamp(line)
			}
			report.recordEndpointHealth(ts, healthy, total)
		}
	}
	items, _ := endpoints["items"].([]any)
	if len(items) == 0 {
		return false
	}
	foundReasons := false
	for _, raw := range items {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		endpoint := jsonString(item["label"])
		account := jsonString(item["account"])
		if account != "" {
			health := report.AccountHealth[account]
			health.Total++
			if !endpointItemUnavailable(item) {
				health.Healthy++
			}
			report.AccountHealth[account] = health
		}
		if reset, ok := jsonNumber(item["quota_reset_sec"]); ok && reset > 0 && endpoint != "" {
			report.Quota = true
			report.addDeployment("quota", endpoint)
			report.QuotaCountdowns[endpoint] = quotaCountdown{
				Account: account,
				Seconds: reset,
			}
		}
		reasons, _ := item["reasons"].(map[string]any)
		for name, rawCount := range reasons {
			count, ok := jsonNumber(rawCount)
			if !ok {
				continue
			}
			key := endpoint
			if key == "" {
				key = account
			}
			recordCumulativeCounter(report.FailureReasons, report.cumulativeFailures, cumulativeSource(key, sourceHint), name, count)
			if count > 0 {
				foundReasons = true
				classifyFailureReason(report, name, endpoint)
			}
		}
	}
	return foundReasons
}

func analyzeHumanEndpointStats(report *analysisReport, line, sourceHint string) bool {
	idx := strings.Index(line, "endpoints:")
	if idx < 0 {
		return false
	}
	detail := strings.TrimSpace(line[idx+len("endpoints:"):])
	if detail == "" || detail == "none" {
		return false
	}
	foundReasons := false
	for _, part := range strings.Split(detail, " | ") {
		part = strings.TrimSpace(part)
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		endpoint := strings.Trim(fields[0], ".,")
		for _, m := range endpointFailureReasons.FindAllStringSubmatch(part, -1) {
			if len(m) != 2 {
				continue
			}
			addFailureReasonCounts(report, cumulativeSource(endpoint, sourceHint), endpoint, reasonCountRe.FindAllStringSubmatch(m[1], -1))
			foundReasons = true
		}
	}
	return foundReasons
}

func analyzeStructuredReplayJSON(report *analysisReport, root map[string]any, component string) {
	replay, _ := root["downstream_replay"].(map[string]any)
	if replay == nil {
		return
	}
	if enabled, _ := replay["enabled"].(bool); enabled {
		report.ReplayEnabled = true
	}
	if active, _ := replay["active"].(bool); active {
		report.ReplayActive = true
	}
	for name, raw := range replay {
		value, ok := jsonNumber(raw)
		if !ok {
			continue
		}
		recordReplayCounter(report, component, name, value)
	}
}

func analyzeReplayFields(report *analysisReport, source, fields string, matches [][]string) {
	if strings.Contains(fields, "enabled=true") || strings.Contains(fields, `"enabled":true`) {
		report.ReplayEnabled = true
	}
	if strings.Contains(fields, "active=true") || strings.Contains(fields, `"active":true`) {
		report.ReplayActive = true
	}
	for _, item := range matches {
		if len(item) != 3 {
			continue
		}
		name := item[1]
		count := parseMetricCount(item[2])
		recordReplayCounter(report, source, name, count)
	}
}

func recordReplayCounter(report *analysisReport, source, name string, count uint64) {
	if isReplayGauge(name) {
		if count > report.ReplayGauges[name] {
			report.ReplayGauges[name] = count
		}
		return
	}
	recordCumulativeCounter(report.ReplayCounters, report.cumulativeReplay, source, name, count)
	if count == 0 {
		return
	}
	switch name {
	case "frames", "bytes", "replay_frames", "replay_bytes":
		report.ReplayHappened = true
	case "dropped_sessions":
		report.ReplayDroppedSessions = true
	case "ack_only_posts":
		if count >= highACKOnlyPosts {
			report.ACKOnlyPostChurn = true
		}
	}
}

func isReplayGauge(name string) bool {
	switch name {
	case "buffer", "buffer_bytes":
		return true
	default:
		return false
	}
}

func recordCumulativeCounter(out, seen map[string]uint64, source, name string, value uint64) {
	key := source + "\x00" + name
	prev, ok := seen[key]
	seen[key] = value
	if !ok || value < prev {
		out[name] += value
		return
	}
	out[name] += value - prev
}

func analyzeStructuredCompressionJSON(report *analysisReport, root map[string]any, component string) {
	payload, _ := root["payload"].(map[string]any)
	if payload == nil {
		return
	}
	compression, _ := payload["compression"].(map[string]any)
	if compression == nil {
		return
	}
	for name, raw := range compression {
		value, ok := jsonNumber(raw)
		if !ok {
			continue
		}
		recordCumulativeCounter(report.CompressionCounters, report.cumulativeCompression, component, name, value)
	}
}

func addCompressionCounters(report *analysisReport, source string, matches [][]string) {
	for _, item := range matches {
		if len(item) != 3 {
			continue
		}
		recordCumulativeCounter(report.CompressionCounters, report.cumulativeCompression, source, item[1], parseMetricCount(item[2]))
	}
}

func endpointItemUnavailable(item map[string]any) bool {
	if reset, ok := jsonNumber(item["quota_reset_sec"]); ok && reset > 0 {
		return true
	}
	if reset, ok := jsonNumber(item["blacklist_reset_sec"]); ok && reset > 0 {
		return true
	}
	return false
}

func addFailureReasonCounts(report *analysisReport, source, endpoint string, matches [][]string) {
	for _, reason := range matches {
		if len(reason) != 3 {
			continue
		}
		name := reason[1]
		count := parseMetricCount(reason[2])
		recordCumulativeCounter(report.FailureReasons, report.cumulativeFailures, source, name, count)
		if count > 0 {
			classifyFailureReason(report, name, endpoint)
		}
	}
}

func jsonString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func jsonNumber(v any) (uint64, bool) {
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case uint64:
		return n, true
	case int:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case int64:
		if n < 0 {
			return 0, false
		}
		return uint64(n), true
	case json.Number:
		parsed, err := strconv.ParseUint(string(n), 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func addReceiveAbortReasonCounts(report *analysisReport, source string, matches [][]string) {
	for _, reason := range matches {
		if len(reason) != 3 {
			continue
		}
		name := reason[1]
		count := atoi(reason[2])
		recordCumulativeCounter(report.ReceiveAbortReasons, report.cumulativeReceiveAbort, source, name, uint64(count))
		if count > 0 {
			report.ReceiveAbort = true
		}
	}
}

func cumulativeSource(source, hint string) string {
	if source == "" {
		source = "unknown"
	}
	if hint == "" {
		return source
	}
	return source + "@" + hint
}

func classifyFailureReason(report *analysisReport, reason, endpoint string) {
	switch reason {
	case "local_offline":
		report.LocalNetworkOutage = true
		report.addDeployment("local_offline", endpoint)
	case "quota":
		report.Quota = true
		report.addDeployment("quota", endpoint)
	case "rate_limit":
		report.RateLimit = true
		report.addDeployment("rate_limit", endpoint)
	case "read_error":
		report.RelayReadError = true
		report.addDeployment("relay_read_error", endpoint)
	case "non_batch", "empty_204", "decode_error":
		report.BadDeploymentOrKey = true
		report.addDeployment("bad_deployment_or_key", endpoint)
	}
}

func (r *analysisReport) addDeployment(signal, endpoint string) {
	if endpoint == "" {
		return
	}
	set := r.DeploymentsBySignal[signal]
	if set == nil {
		set = map[string]struct{}{}
		r.DeploymentsBySignal[signal] = set
	}
	set[endpoint] = struct{}{}
}

func (r *analysisReport) hasDeploymentSignal(signal, endpoint string) bool {
	if endpoint == "" {
		return false
	}
	set := r.DeploymentsBySignal[signal]
	if set == nil {
		return false
	}
	_, ok := set[endpoint]
	return ok
}

func (r *analysisReport) recordTargetFailure(target string, suppressed bool) {
	target = strings.TrimSpace(target)
	if target == "" {
		return
	}
	summary := r.TargetFailures[target]
	if summary == nil {
		summary = &targetFailureSummary{}
		r.TargetFailures[target] = summary
	}
	if suppressed {
		summary.Suppressed++
	} else {
		summary.Fail++
	}
}

func (r *analysisReport) recordSlowTarget(target string, ttfbMS, firstReadMS int) {
	target = strings.Trim(target, ".,")
	if target == "" {
		return
	}
	summary := r.SlowTargets[target]
	if summary == nil {
		summary = &slowTargetSummary{}
		r.SlowTargets[target] = summary
	}
	if ttfbMS > summary.TTFBMaxMS {
		summary.TTFBMaxMS = ttfbMS
	}
	if firstReadMS > summary.FirstReadMaxMS {
		summary.FirstReadMaxMS = firstReadMS
	}
}

func (r *analysisReport) recordResponseBatch(batch responseBatchSummary) {
	if batch.RespBytes <= 0 {
		return
	}
	r.ResponseBatches = append(r.ResponseBatches, batch)
	sort.Slice(r.ResponseBatches, func(i, j int) bool {
		if r.ResponseBatches[i].RespBytes == r.ResponseBatches[j].RespBytes {
			return r.ResponseBatches[i].RTTMS > r.ResponseBatches[j].RTTMS
		}
		return r.ResponseBatches[i].RespBytes > r.ResponseBatches[j].RespBytes
	})
	if len(r.ResponseBatches) > 5 {
		r.ResponseBatches = r.ResponseBatches[:5]
	}
}

func renderReport(report analysisReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "GooseRelayVPN log analysis\n")
	fmt.Fprintf(&b, "files: %d\n", len(report.Files))
	fmt.Fprintf(&b, "lines: %d\n", report.Lines)
	fmt.Fprintf(&b, "quota: %s\n", yesNo(report.Quota))
	fmt.Fprintf(&b, "rate limit: %s\n", yesNo(report.RateLimit))
	fmt.Fprintf(&b, "local network outage: %s\n", yesNo(report.LocalNetworkOutage))
	fmt.Fprintf(&b, "bad deployment/key/protocol: %s\n", yesNo(report.BadDeploymentOrKey))
	fmt.Fprintf(&b, "google/fronting slow: %s", yesNo(report.GoogleFrontingSlow))
	if report.MaxGoogleRTTMS > 0 {
		fmt.Fprintf(&b, " (max poll RTT %dms)", report.MaxGoogleRTTMS)
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "upstream/warp slow: %s", yesNo(report.UpstreamOrWARPSlow))
	if report.MaxUpstreamFirstReadMS > 0 {
		fmt.Fprintf(&b, " (max first_read %dms)", report.MaxUpstreamFirstReadMS)
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "queue wait high: %s", yesNo(report.QueueWaitHigh))
	if report.MaxQueueWaitP95MS > 0 {
		fmt.Fprintf(&b, " (max p95 %dms)", report.MaxQueueWaitP95MS)
	}
	b.WriteString("\n")
	fmt.Fprintf(&b, "receive aborts: %s\n", yesNo(report.ReceiveAbort))
	fmt.Fprintf(&b, "single relay endpoint: %s\n", yesNo(report.SingleRelayEndpoint))
	fmt.Fprintf(&b, "downstream replay enabled: %s\n", yesNo(report.ReplayEnabled))
	fmt.Fprintf(&b, "downstream replay active: %s\n", yesNo(report.ReplayActive))
	fmt.Fprintf(&b, "downstream replay happened: %s\n", yesNo(report.ReplayHappened))
	fmt.Fprintf(&b, "downstream replay session resets: %s\n", yesNo(report.ReplayDroppedSessions))
	renderDeployments(&b, report.DeploymentsBySignal)
	renderFailureReasons(&b, report.FailureReasons)
	renderReceiveAbortReasons(&b, report.ReceiveAbortReasons)
	renderReplayCounters(&b, report.ReplayCounters)
	renderReplayGauges(&b, report.ReplayGauges)
	renderCompressionCounters(&b, report.CompressionCounters)
	renderEndpointTimeline(&b, report.EndpointTimeline)
	renderQuotaCountdowns(&b, report.QuotaCountdowns)
	renderAccountHealth(&b, report.AccountHealth)
	renderTargetFailures(&b, report.TargetFailures)
	renderSlowTargets(&b, report.SlowTargets)
	renderLargestResponseBatches(&b, report.ResponseBatches)
	renderRecommendations(&b, report)
	return b.String()
}

func renderDeployments(b *strings.Builder, bySignal map[string]map[string]struct{}) {
	if len(bySignal) == 0 {
		return
	}
	b.WriteString("deployments:\n")
	signals := sortedKeys(bySignal)
	for _, signal := range signals {
		fmt.Fprintf(b, "- %s: %s\n", signal, strings.Join(sortedSet(bySignal[signal]), ", "))
	}
}

func renderFailureReasons(b *strings.Builder, reasons map[string]uint64) {
	if len(reasons) == 0 {
		return
	}
	b.WriteString("failure reasons:\n")
	keys := sortedKeysUint(reasons)
	for _, key := range keys {
		fmt.Fprintf(b, "- %s=%d\n", key, reasons[key])
	}
}

func renderReceiveAbortReasons(b *strings.Builder, reasons map[string]uint64) {
	if len(reasons) == 0 {
		return
	}
	b.WriteString("receive abort reasons:\n")
	keys := sortedKeysUint(reasons)
	for _, key := range keys {
		fmt.Fprintf(b, "- %s=%d\n", key, reasons[key])
	}
}

func renderReplayCounters(b *strings.Builder, counters map[string]uint64) {
	if len(counters) == 0 {
		return
	}
	b.WriteString("downstream replay counters:\n")
	keys := sortedKeysUint(counters)
	for _, key := range keys {
		fmt.Fprintf(b, "- %s=%d\n", key, counters[key])
	}
}

func renderReplayGauges(b *strings.Builder, gauges map[string]uint64) {
	if len(gauges) == 0 {
		return
	}
	b.WriteString("downstream replay gauges (max observed):\n")
	keys := sortedKeysUint(gauges)
	for _, key := range keys {
		fmt.Fprintf(b, "- %s=%d\n", key, gauges[key])
	}
}

func renderCompressionCounters(b *strings.Builder, counters map[string]uint64) {
	if len(counters) == 0 {
		return
	}
	b.WriteString("compression:\n")
	keys := sortedKeysUint(counters)
	for _, key := range keys {
		fmt.Fprintf(b, "- %s=%d\n", key, counters[key])
	}
}

func renderEndpointTimeline(b *strings.Builder, timeline []endpointTimelineEntry) {
	if len(timeline) == 0 {
		return
	}
	b.WriteString("endpoint timeline:\n")
	for _, item := range timeline {
		ts := item.TS
		if ts == "" {
			ts = "unknown-time"
		}
		fmt.Fprintf(b, "- %s healthy=%d/%d\n", ts, item.Healthy, item.Total)
	}
}

func renderQuotaCountdowns(b *strings.Builder, countdowns map[string]quotaCountdown) {
	if len(countdowns) == 0 {
		return
	}
	b.WriteString("quota reset countdowns:\n")
	for _, endpoint := range sortedKeys(countdowns) {
		item := countdowns[endpoint]
		if item.Account != "" {
			fmt.Fprintf(b, "- %s account=%s quota_reset=%ds\n", endpoint, item.Account, item.Seconds)
		} else {
			fmt.Fprintf(b, "- %s quota_reset=%ds\n", endpoint, item.Seconds)
		}
	}
}

func renderAccountHealth(b *strings.Builder, accounts map[string]accountHealth) {
	if len(accounts) == 0 {
		return
	}
	b.WriteString("healthy accounts over time:\n")
	for _, account := range sortedKeys(accounts) {
		item := accounts[account]
		fmt.Fprintf(b, "- %s healthy=%d/%d\n", account, item.Healthy, item.Total)
	}
}

func renderTargetFailures(b *strings.Builder, targets map[string]*targetFailureSummary) {
	if len(targets) == 0 {
		return
	}
	keys := sortedTargetFailures(targets)
	b.WriteString("top failed targets:\n")
	for i, target := range keys {
		if i >= 10 {
			break
		}
		item := targets[target]
		fmt.Fprintf(b, "- %s fail=%d suppressed=%d\n", target, item.Fail, item.Suppressed)
	}
}

func renderSlowTargets(b *strings.Builder, targets map[string]*slowTargetSummary) {
	if len(targets) == 0 {
		return
	}
	keys := sortedSlowTargets(targets)
	b.WriteString("top slow targets:\n")
	for i, target := range keys {
		if i >= 10 {
			break
		}
		item := targets[target]
		parts := []string{}
		if item.TTFBMaxMS > 0 {
			parts = append(parts, fmt.Sprintf("ttfb_max=%dms", item.TTFBMaxMS))
		}
		if item.FirstReadMaxMS > 0 {
			parts = append(parts, fmt.Sprintf("first_read_max=%dms", item.FirstReadMaxMS))
		}
		fmt.Fprintf(b, "- %s %s\n", target, strings.Join(parts, " "))
	}
}

func renderLargestResponseBatches(b *strings.Builder, batches []responseBatchSummary) {
	if len(batches) == 0 {
		return
	}
	b.WriteString("largest response batches:\n")
	for _, batch := range batches {
		endpoint := batch.Endpoint
		if endpoint == "" {
			endpoint = "unknown-endpoint"
		}
		fmt.Fprintf(b, "- %s resp=%dB rtt=%dms rx=%d tx=%d\n", endpoint, batch.RespBytes, batch.RTTMS, batch.RXFrames, batch.TXFrames)
	}
}

func renderRecommendations(b *strings.Builder, report analysisReport) {
	b.WriteString("recommendations:\n")
	singleEndpointRelayFailure := hasSingleEndpointRelayFailure(report)
	if report.Quota {
		b.WriteString("- quota evidence found: add more Google accounts/deployments or wait for the Pacific reset.\n")
	}
	if report.RateLimit {
		b.WriteString("- rate-limit evidence found: reduce per-account concurrency or add more labeled Google account buckets.\n")
	}
	if report.LocalNetworkOutage {
		b.WriteString("- local outage evidence found: focus on phone/network recovery behavior before redeploying scripts.\n")
	}
	if report.BadDeploymentOrKey {
		b.WriteString("- bad deployment/key/protocol evidence found: verify tunnel_key, Apps Script deployment access, and stale deployments.\n")
	}
	if report.GoogleFrontingSlow {
		b.WriteString("- Google/fronting RTT is high: try alternate google_host/SNI combinations and compare timing logs.\n")
	}
	if report.UpstreamOrWARPSlow {
		b.WriteString("- upstream/WARP first_read is high: compare WARP on/off and VPS DNS/route timings.\n")
	}
	if report.QueueWaitHigh {
		b.WriteString("- queue wait is high: tune active drain/coalesce windows or reduce concurrent bulk load.\n")
	}
	if report.ReceiveAbortReasons["rx_reorder_overflow"] > 0 {
		b.WriteString("- rx_reorder_overflow found: downstream frames arrived after a sequence gap, usually from a lost relay response; try smaller max_response_bytes_pre_encode on mobile links.\n")
		if !report.ReplayEnabled && !report.ReplayActive {
			b.WriteString("- sequence gaps while replay is off: enable downstream replay for mobile tests (client downstream_replay_mode=\"auto\", server downstream_replay_enabled=true).\n")
		}
	}
	if report.ReceiveAbortReasons["rx_inbox_timeout"] > 0 {
		b.WriteString("- rx_inbox_timeout found: local SOCKS consumer paused long enough to fill the receive inbox; capture Android memory/CPU and consider smaller response batches.\n")
	}
	if report.RelayReadError && !report.ReplayEnabled && !report.ReplayActive {
		b.WriteString("- relay response read errors while replay is off: enable downstream replay before judging large-download reliability.\n")
	}
	if report.HTTP2FrontingIssue || (report.GoogleFrontingSlow && report.MaxGoogleRTTMS >= 3000) {
		b.WriteString("- HTTP/2/fronting instability suspected: test client fronting_http_version: \"h1\" on the same network and compare logs.\n")
	}
	if report.IdleQuotaBurn {
		b.WriteString("- idle polls are burning quota without useful traffic: set idle_poll_mode to \"adaptive\" or \"off\" for 24/7 background use.\n")
	}
	if report.ACKOnlyPostChurn {
		b.WriteString("- ACK-only POST churn is high: keep the current low-latency behavior for browsing, but capture a short debug_timing test before considering a tiny ACK-only coalesce window.\n")
	}
	if singleEndpointRelayFailure {
		b.WriteString("- single relay endpoint had failures: add a backup deployment on another Google account so one 404/non-batch/error page does not stall every active session.\n")
	}
	if report.ReplayHappened {
		b.WriteString("- downstream replay occurred: the tunnel recovered at least one likely lost downstream HTTP response; keep replay enabled for mobile testing.\n")
	}
	if report.ReplayDroppedSessions {
		b.WriteString("- downstream replay reset sessions: check server logs for whether this was replay expiry or a memory/frame cap. Expiry usually means stale or unacked mobile sessions; cap drops mean response batches or replay limits are too aggressive.\n")
	}
	if !report.Quota && !report.RateLimit && !report.LocalNetworkOutage && !report.BadDeploymentOrKey &&
		!report.GoogleFrontingSlow && !report.UpstreamOrWARPSlow && !report.QueueWaitHigh && !report.ReceiveAbort &&
		!report.RelayReadError && !report.HTTP2FrontingIssue && !report.IdleQuotaBurn && !report.ACKOnlyPostChurn &&
		!singleEndpointRelayFailure && !report.ReplayHappened && !report.ReplayDroppedSessions {
		b.WriteString("- no strong failure signal found; capture logs with debug_timing and stats_json enabled during the next issue.\n")
	}
}

func hasSingleEndpointRelayFailure(report analysisReport) bool {
	return report.SingleRelayEndpoint &&
		(report.BadDeploymentOrKey ||
			report.RelayReadError ||
			report.FailureReasons["http_error"] > 0 ||
			report.FailureReasons["non_batch"] > 0)
}

func readLogText(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return decodeLogBytes(data), nil
}

func decodeLogBytes(data []byte) string {
	if len(data) >= 2 {
		switch {
		case data[0] == 0xff && data[1] == 0xfe:
			return decodeUTF16(data[2:], binary.LittleEndian)
		case data[0] == 0xfe && data[1] == 0xff:
			return decodeUTF16(data[2:], binary.BigEndian)
		}
	}
	if looksUTF16LE(data) {
		return decodeUTF16(data, binary.LittleEndian)
	}
	if looksUTF16BE(data) {
		return decodeUTF16(data, binary.BigEndian)
	}
	return string(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
}

func decodeUTF16(data []byte, order binary.ByteOrder) string {
	if len(data)%2 == 1 {
		data = data[:len(data)-1]
	}
	u16 := make([]uint16, 0, len(data)/2)
	for len(data) >= 2 {
		u16 = append(u16, order.Uint16(data[:2]))
		data = data[2:]
	}
	if len(u16) > 0 && u16[0] == 0xfeff {
		u16 = u16[1:]
	}
	return string(utf16.Decode(u16))
}

func looksUTF16LE(data []byte) bool {
	return looksUTF16(data, 1)
}

func looksUTF16BE(data []byte) bool {
	return looksUTF16(data, 0)
}

func looksUTF16(data []byte, zeroOffset int) bool {
	if len(data) < 8 {
		return false
	}
	limit := len(data)
	if limit > 256 {
		limit = 256
	}
	pairs, zeros := 0, 0
	for i := zeroOffset; i+1 < limit; i += 2 {
		pairs++
		if data[i] == 0 {
			zeros++
		}
	}
	return pairs > 0 && zeros*2 >= pairs
}

func endpointFromLine(line string) string {
	if m := endpointViaRe.FindStringSubmatch(line); len(m) == 2 {
		return strings.Trim(m[1], ".,")
	}
	if m := endpointStatsRe.FindStringSubmatch(line); len(m) == 2 {
		return strings.Trim(m[1], ".,")
	}
	return ""
}

func lineTimestamp(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func parseMetricCount(s string) uint64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0
	}
	mult := float64(1)
	for _, suffix := range []struct {
		s string
		m float64
	}{
		{"GB", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
		{"KB", 1024},
		{"B", 1},
	} {
		if strings.HasSuffix(s, suffix.s) {
			mult = suffix.m
			s = strings.TrimSuffix(s, suffix.s)
			break
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 {
		return 0
	}
	return uint64(f*mult + 0.5)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeysUint(m map[string]uint64) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedSet(set map[string]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func sortedTargetFailures(targets map[string]*targetFailureSummary) []string {
	keys := sortedKeys(targets)
	sort.SliceStable(keys, func(i, j int) bool {
		a := targets[keys[i]]
		b := targets[keys[j]]
		aTotal := a.Fail + a.Suppressed
		bTotal := b.Fail + b.Suppressed
		if aTotal == bTotal {
			return keys[i] < keys[j]
		}
		return aTotal > bTotal
	})
	return keys
}

func sortedSlowTargets(targets map[string]*slowTargetSummary) []string {
	keys := sortedKeys(targets)
	sort.SliceStable(keys, func(i, j int) bool {
		a := targets[keys[i]]
		b := targets[keys[j]]
		aMax := a.TTFBMaxMS
		if a.FirstReadMaxMS > aMax {
			aMax = a.FirstReadMaxMS
		}
		bMax := b.TTFBMaxMS
		if b.FirstReadMaxMS > bMax {
			bMax = b.FirstReadMaxMS
		}
		if aMax == bMax {
			return keys[i] < keys[j]
		}
		return aMax > bMax
	})
	return keys
}
