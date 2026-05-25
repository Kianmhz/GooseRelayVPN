package carrier

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/metrics"
)

// statsInterval is how often the periodic stats line is logged. Long enough
// to be unobtrusive, short enough to spot trends within a single session.
const statsInterval = 60 * time.Second

// runStatsLoop periodically emits a one-line summary of carrier health so a
// developer can spot drift (rising RST count, blacklisted endpoints, etc.)
// without grepping for individual events. Returns when ctx is canceled.
func (c *Client) runStatsLoop(ctx context.Context) {
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.logStats()
		}
	}
}

func (c *Client) logStats() {
	c.mu.Lock()
	active := len(c.sessions)
	c.mu.Unlock()

	healthy, total := c.endpointHealthCounts()
	endpointDetail := c.endpointStatsLine()
	accountSummary := c.accountStatsLine()

	if c.statsJSON {
		c.logStatsJSON(active, healthy, total, endpointDetail, accountSummary)
		return
	}

	log.Printf("[stats] active=%d sessions=%d/%d frames=%d/%d bytes=%s/%s polls(ok=%d fail=%d useful=%d empty=%d idle=%d suppress=%d idle_busy=%d active_busy=%d) rst=%d endpoints=%d/%d",
		active,
		c.stats.sessionsOpen.Load(), c.stats.sessionsClose.Load(),
		c.stats.framesOut.Load(), c.stats.framesIn.Load(),
		humanBytes(c.stats.bytesOut.Load()), humanBytes(c.stats.bytesIn.Load()),
		c.stats.pollsOK.Load(), c.stats.pollsFail.Load(),
		c.stats.usefulPolls.Load(), c.stats.emptyPolls.Load(),
		c.stats.idlePolls.Load(), c.stats.idleSuppressed.Load(), c.stats.idleSlotBusy.Load(), c.stats.activeSlotBusy.Load(),
		c.stats.rstFromServer.Load(),
		healthy, total,
	)
	log.Printf("[stats] latency ttfb[%s] endpoint_rtt[%s] queue_wait[%s] encode[%s] decode[%s]",
		c.stats.ttfb.Snapshot().StringMS(),
		c.stats.endpointRTT.Snapshot().StringMS(),
		c.stats.queueWait.Snapshot().StringMS(),
		c.stats.encode.Snapshot().StringMS(),
		c.stats.decode.Snapshot().StringMS(),
	)
	log.Printf("[stats] payload req={%s} resp={%s} wire_ratio={%s} stream(ok=%d fail=%d drop=%d post_fallback=%d)",
		c.stats.reqSize.String(),
		c.stats.respSize.String(),
		c.stats.wireRatio.String(),
		c.stats.streamOK.Load(),
		c.stats.streamFail.Load(),
		c.stats.streamDrops.Load(),
		c.stats.postFallbacks.Load(),
	)
	if compression := c.compressionStatsMap(); len(compression) > 0 {
		log.Printf("[stats] compression modes(raw=%d zstd=%d) attempted=%d used=%d skipped=%d raw_bytes=%s body_bytes=%s wire_bytes=%s saved_bytes=%s lost_bytes=%s",
			compression["raw"], compression["zstd"],
			compression["attempted"], compression["used"], compression["skipped"],
			humanBytes(compression["raw_bytes"]), humanBytes(compression["body_bytes"]),
			humanBytes(compression["wire_bytes"]), humanBytes(compression["saved_bytes"]),
			humanBytes(compression["lost_bytes"]),
		)
	}
	log.Printf("[stats] replay active=%t ack_sent=%d ack_only_posts=%d ack_only_frames=%d",
		c.downstreamReplayActive.Load(),
		c.stats.ackSent.Load(),
		c.stats.ackOnlyPosts.Load(),
		c.stats.ackOnlyFrames.Load(),
	)
	if receiveAbort := c.receiveAbortStatsLine(); receiveAbort != "" {
		log.Printf("[stats] receive_abort={%s}", receiveAbort)
	}
	log.Printf("[stats] endpoints: %s", endpointDetail)
	if accountSummary != "" {
		log.Printf("[stats] %s", strings.TrimSpace(accountSummary))
	}
}

func (c *Client) logStatsJSON(active, healthy, total int, endpointDetail, accountSummary string) {
	payload := map[string]any{
		"event":     "stats",
		"component": "carrier",
		"ts":        time.Now().Format(time.RFC3339),
		"active":    active,
		"sessions": map[string]uint64{
			"open":  c.stats.sessionsOpen.Load(),
			"close": c.stats.sessionsClose.Load(),
		},
		"frames": map[string]uint64{
			"out": c.stats.framesOut.Load(),
			"in":  c.stats.framesIn.Load(),
		},
		"bytes": map[string]uint64{
			"out": c.stats.bytesOut.Load(),
			"in":  c.stats.bytesIn.Load(),
		},
		"polls": map[string]uint64{
			"ok":               c.stats.pollsOK.Load(),
			"fail":             c.stats.pollsFail.Load(),
			"useful":           c.stats.usefulPolls.Load(),
			"empty":            c.stats.emptyPolls.Load(),
			"idle":             c.stats.idlePolls.Load(),
			"idle_suppressed":  c.stats.idleSuppressed.Load(),
			"idle_slot_busy":   c.stats.idleSlotBusy.Load(),
			"active_slot_busy": c.stats.activeSlotBusy.Load(),
		},
		"rst_from_server": c.stats.rstFromServer.Load(),
		"endpoints": map[string]any{
			"healthy":                healthy,
			"total":                  total,
			"detail":                 endpointDetail,
			"items":                  c.endpointStatsItems(),
			"active_slots_by_bucket": c.activeSlotsByBucket(),
			"tx_slot_limit":          c.txSlotsPerBucket,
		},
		"latency_ms": map[string]any{
			"ttfb":         durationSummaryJSON(c.stats.ttfb.Snapshot()),
			"endpoint_rtt": durationSummaryJSON(c.stats.endpointRTT.Snapshot()),
			"queue_wait":   durationSummaryJSON(c.stats.queueWait.Snapshot()),
			"encode":       durationSummaryJSON(c.stats.encode.Snapshot()),
			"decode":       durationSummaryJSON(c.stats.decode.Snapshot()),
		},
		"payload": map[string]any{
			"request_size_buckets":  c.stats.reqSize.Snapshot(),
			"response_size_buckets": c.stats.respSize.Snapshot(),
			"wire_ratio_buckets":    c.stats.wireRatio.Snapshot(),
			"compression":           c.compressionStatsMap(),
		},
		"stream": map[string]uint64{
			"ok":            c.stats.streamOK.Load(),
			"fail":          c.stats.streamFail.Load(),
			"drop":          c.stats.streamDrops.Load(),
			"post_fallback": c.stats.postFallbacks.Load(),
		},
		"downstream_replay": map[string]any{
			"active":          c.downstreamReplayActive.Load(),
			"ack_sent":        c.stats.ackSent.Load(),
			"ack_only_posts":  c.stats.ackOnlyPosts.Load(),
			"ack_only_frames": c.stats.ackOnlyFrames.Load(),
		},
	}
	if strings.TrimSpace(accountSummary) != "" {
		payload["accounts"] = strings.TrimSpace(accountSummary)
		payload["account_items"] = c.accountStatsItems()
	}
	if receiveAbort := c.receiveAbortStatsMap(); len(receiveAbort) > 0 {
		payload["receive_abort"] = receiveAbort
	}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[stats] json marshal failed: %v", err)
		return
	}
	log.Printf("[stats_json] %s", body)
}

func (c *Client) activeSlotsByBucket() map[string]int {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if len(c.activeByBucket) == 0 {
		return nil
	}
	out := make(map[string]int, len(c.activeByBucket))
	for bucket, count := range c.activeByBucket {
		if count > 0 {
			out[bucket] = count
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (c *Client) compressionStatsMap() map[string]uint64 {
	stats := map[string]uint64{
		"attempted":   c.stats.compressAttempted.Load(),
		"used":        c.stats.compressUsed.Load(),
		"skipped":     c.stats.compressSkipped.Load(),
		"raw":         c.stats.compressRaw.Load(),
		"zstd":        c.stats.compressZstd.Load(),
		"raw_bytes":   c.stats.compressRawBytes.Load(),
		"body_bytes":  c.stats.compressBodyBytes.Load(),
		"wire_bytes":  c.stats.compressWireBytes.Load(),
		"saved_bytes": c.stats.compressSaved.Load(),
		"lost_bytes":  c.stats.compressLost.Load(),
	}
	if stats["attempted"] == 0 && stats["skipped"] == 0 && stats["raw"] == 0 && stats["zstd"] == 0 {
		return nil
	}
	return stats
}

func durationSummaryJSON(s metrics.DurationSummary) map[string]any {
	return map[string]any{
		"count": s.Count,
		"p50":   s.P50.Milliseconds(),
		"p95":   s.P95.Milliseconds(),
		"p99":   s.P99.Milliseconds(),
	}
}

func (c *Client) endpointHealthCounts() (healthy, total int) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	now := time.Now()
	total = len(c.endpoints)
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if !c.endpointUnavailableLocked(ep, now) {
			healthy++
		}
	}
	return
}

func (c *Client) endpointStatsLine() string {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if len(c.endpoints) == 0 {
		return "none"
	}
	now := time.Now()
	parts := make([]string, 0, len(c.endpoints))
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		c.touchDailyWindow(ep, now)
		today := fmt.Sprintf("today=%d", ep.dailyCount)
		label := shortScriptKey(ep.url)
		if ep.account != "" {
			// `@account` annotation lets the operator visually match each
			// deployment to its account row in the accounts=[...] aggregation
			// without cross-referencing the config file.
			label = label + "@" + ep.account
		}
		part := fmt.Sprintf("%s ok=%d fail=%d %s", label, ep.statsOK, ep.statsFail, today)
		if reasons := endpointFailureReasonsLine(ep); reasons != "" {
			part = fmt.Sprintf("%s %s", part, reasons)
		}
		if ep.rttEWMA > 0 {
			part = fmt.Sprintf("%s rtt=%dms", part, ep.rttEWMA.Milliseconds())
		}
		if !ep.scriptCountAt.IsZero() {
			// Script-reported approximate web-app request count from doGet. May
			// lag the client-side count by up to scriptStatsInterval; it is a
			// pressure signal, not an exact Google UrlFetch quota meter.
			part = fmt.Sprintf("%s script=%d", part, ep.scriptCount)
		}
		if ep.blacklistedTill.After(now) {
			remaining := time.Until(ep.blacklistedTill).Round(time.Second)
			part = fmt.Sprintf("%s bl=%s", part, remaining)
		}
		if ep.quotaExhaustedUntil.After(now) {
			remaining := time.Until(ep.quotaExhaustedUntil).Round(time.Second)
			part = fmt.Sprintf("%s quota_reset=%s", part, remaining)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " | ")
}

func endpointFailureReasonsLine(ep *relayEndpoint) string {
	parts := make([]string, 0, len(ep.failureReasons))
	for i, count := range ep.failureReasons {
		if count == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", endpointFailureReasonLabels[i], count))
	}
	if len(parts) == 0 {
		return ""
	}
	return "reasons={" + strings.Join(parts, " ") + "}"
}

func endpointFailureReasonsMap(ep *relayEndpoint) map[string]uint64 {
	reasons := map[string]uint64{}
	for i, count := range ep.failureReasons {
		if count == 0 {
			continue
		}
		reasons[endpointFailureReasonLabels[i]] = count
	}
	return reasons
}

func (c *Client) endpointStatsItems() []map[string]any {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if len(c.endpoints) == 0 {
		return nil
	}
	now := time.Now()
	items := make([]map[string]any, 0, len(c.endpoints))
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		c.touchDailyWindow(ep, now)
		label := shortScriptKey(ep.url)
		item := map[string]any{
			"label": label,
			"ok":    ep.statsOK,
			"fail":  ep.statsFail,
			"today": ep.dailyCount,
		}
		if ep.account != "" {
			item["account"] = ep.account
		}
		if reasons := endpointFailureReasonsMap(ep); len(reasons) > 0 {
			item["reasons"] = reasons
		}
		if ep.rttEWMA > 0 {
			item["rtt_ms"] = ep.rttEWMA.Milliseconds()
		}
		if !ep.scriptCountAt.IsZero() {
			item["script"] = ep.scriptCount
		}
		if ep.blacklistedTill.After(now) {
			item["blacklist_reset_sec"] = int64(ep.blacklistedTill.Sub(now).Round(time.Second).Seconds())
		}
		if ep.quotaExhaustedUntil.After(now) {
			item["quota_reset_sec"] = int64(ep.quotaExhaustedUntil.Sub(now).Round(time.Second).Seconds())
		}
		items = append(items, item)
	}
	return items
}

func (c *Client) recordReceiveAbort(reason string) {
	switch reason {
	case "rx_inbox_timeout":
		c.stats.rxInboxTimeout.Add(1)
	case "rx_reorder_overflow":
		c.stats.rxReorderOverflow.Add(1)
	default:
		c.stats.rxAbortOther.Add(1)
	}
}

func (c *Client) receiveAbortStatsLine() string {
	m := c.receiveAbortStatsMap()
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, " ")
}

func (c *Client) receiveAbortStatsMap() map[string]uint64 {
	m := map[string]uint64{}
	if v := c.stats.rxInboxTimeout.Load(); v > 0 {
		m["rx_inbox_timeout"] = v
	}
	if v := c.stats.rxReorderOverflow.Load(); v > 0 {
		m["rx_reorder_overflow"] = v
	}
	if v := c.stats.rxAbortOther.Load(); v > 0 {
		m["other"] = v
	}
	return m
}

// accountStatsLine returns " accounts=[...]" suffix when at least one
// endpoint carries an account label, or "" otherwise. Aggregates the daily
// client-side count and (when available) the script-reported count per
// account so the operator can directly read each Google account's approximate
// request pressure against its ~20k/day UrlFetch quota.
//
// scriptCount aggregation is dedup-by-value, not sum: PropertiesService is
// per Apps Script project, so multiple deployments of one project all report
// the same count. Summing them would multiply the project's true count by
// the deployment fan-out (issue surfaced when a user with 2 deployments of
// 1 project per account saw `script` reported at 2× the doGet value).
// Distinct projects under one account give distinct counts and are still
// summed correctly; the only edge is two different projects coincidentally
// at the same count, which would undercount by one — negligible at the
// thousand-call scale these counters operate at.
func (c *Client) accountStatsLine() string {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	type agg struct {
		today        uint64
		scriptCounts map[uint64]struct{} // distinct script-reported counts seen for this account
	}
	totals := map[string]*agg{}
	now := time.Now()
	hasAny := false
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if ep.account == "" {
			continue
		}
		hasAny = true
		c.touchDailyWindow(ep, now)
		a, ok := totals[ep.account]
		if !ok {
			a = &agg{scriptCounts: map[uint64]struct{}{}}
			totals[ep.account] = a
		}
		a.today += ep.dailyCount
		if !ep.scriptCountAt.IsZero() {
			a.scriptCounts[ep.scriptCount] = struct{}{}
		}
	}
	if !hasAny {
		return ""
	}

	names := make([]string, 0, len(totals))
	for name := range totals {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		a := totals[name]
		s := fmt.Sprintf("%s today=%d", name, a.today)
		if len(a.scriptCounts) > 0 {
			var script uint64
			for v := range a.scriptCounts {
				script += v
			}
			s = fmt.Sprintf("%s script=%d", s, script)
		}
		parts = append(parts, s)
	}
	return " accounts=[" + strings.Join(parts, " | ") + "]"
}

func (c *Client) accountStatsItems() []map[string]any {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()

	type agg struct {
		today        uint64
		scriptCounts map[uint64]struct{}
	}
	totals := map[string]*agg{}
	now := time.Now()
	for i := range c.endpoints {
		ep := &c.endpoints[i]
		if ep.account == "" {
			continue
		}
		c.touchDailyWindow(ep, now)
		a, ok := totals[ep.account]
		if !ok {
			a = &agg{scriptCounts: map[uint64]struct{}{}}
			totals[ep.account] = a
		}
		a.today += ep.dailyCount
		if !ep.scriptCountAt.IsZero() {
			a.scriptCounts[ep.scriptCount] = struct{}{}
		}
	}
	if len(totals) == 0 {
		return nil
	}

	names := make([]string, 0, len(totals))
	for name := range totals {
		names = append(names, name)
	}
	sort.Strings(names)

	items := make([]map[string]any, 0, len(names))
	for _, name := range names {
		a := totals[name]
		item := map[string]any{
			"account": name,
			"today":   a.today,
		}
		if len(a.scriptCounts) > 0 {
			var script uint64
			for v := range a.scriptCounts {
				script += v
			}
			item["script"] = script
		}
		items = append(items, item)
	}
	return items
}

// humanBytes formats a byte count as a short human-readable string. Used for
// stats lines that an operator scans visually.
func humanBytes(n uint64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%dB", n)
	case n < k*k:
		return fmt.Sprintf("%.1fKB", float64(n)/float64(k))
	case n < k*k*k:
		return fmt.Sprintf("%.1fMB", float64(n)/float64(k*k))
	default:
		return fmt.Sprintf("%.2fGB", float64(n)/float64(k*k*k))
	}
}
