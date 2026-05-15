package carrier

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"
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

	log.Printf("[stats] active=%d sessions=%d/%d frames=%d/%d bytes=%s/%s polls=%d/%d rst=%d endpoints=%d/%d",
		active,
		c.stats.sessionsOpen.Load(), c.stats.sessionsClose.Load(),
		c.stats.framesOut.Load(), c.stats.framesIn.Load(),
		humanBytes(c.stats.bytesOut.Load()), humanBytes(c.stats.bytesIn.Load()),
		c.stats.pollsOK.Load(), c.stats.pollsFail.Load(),
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
	log.Printf("[stats] endpoints: %s", endpointDetail)
	if accountSummary != "" {
		log.Printf("[stats] %s", strings.TrimSpace(accountSummary))
	}
}

func (c *Client) endpointHealthCounts() (healthy, total int) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	now := time.Now()
	total = len(c.endpoints)
	for _, ep := range c.endpoints {
		if !ep.blacklistedTill.After(now) {
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
		if !ep.scriptCountAt.IsZero() {
			// Script-reported count from doGet. May lag the client-side count
			// by up to scriptStatsInterval; a divergence means the deployment
			// is also being hit by other clients or by manual /exec probes.
			part = fmt.Sprintf("%s script=%d", part, ep.scriptCount)
		}
		if ep.blacklistedTill.After(now) {
			remaining := time.Until(ep.blacklistedTill).Round(time.Second)
			part = fmt.Sprintf("%s bl=%s", part, remaining)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " | ")
}

// accountStatsLine returns " accounts=[...]" suffix when at least one
// endpoint carries an account label, or "" otherwise. Aggregates the daily
// client-side count and (when available) the script-reported count per
// account so the operator can directly read each Google account's spend
// against its ~20k/day quota.
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
