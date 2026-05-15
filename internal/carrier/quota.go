package carrier

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
)

// quotaResetTZ is the Apps Script quota reset timezone. Google resets the
// per-account UrlFetch quota at midnight Pacific. Loaded once at init; falls
// back to a fixed -08:00 zone if the system tzdata is unavailable so the
// reset boundary is still computable in stripped-down container images.
var quotaResetTZ = func() *time.Location {
	if loc, err := time.LoadLocation("America/Los_Angeles"); err == nil {
		return loc
	}
	return time.FixedZone("PST", -8*3600)
}()

// nextQuotaReset returns the next midnight in the Apps Script quota timezone
// strictly after now. The returned instant is when the dailyCount counter
// should be zeroed for endpoints whose last reset was before this point.
func nextQuotaReset(now time.Time) time.Time {
	local := now.In(quotaResetTZ)
	midnight := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, quotaResetTZ)
	if !midnight.After(now) {
		midnight = time.Date(local.Year(), local.Month(), local.Day()+1, 0, 0, 0, 0, quotaResetTZ)
	}
	return midnight
}

// touchDailyWindow rolls over the daily counter when the previous window has
// elapsed. Returns whether a rollover occurred so the caller can log it
// outside the endpointMu critical section.
//
// Caller must hold c.endpointMu.
func (c *Client) touchDailyWindow(ep *relayEndpoint, now time.Time) (rolledOver bool) {
	if ep.dailyResetAt.IsZero() {
		ep.dailyResetAt = nextQuotaReset(now)
		return false
	}
	if now.Before(ep.dailyResetAt) {
		return false
	}
	expiredReset := ep.dailyResetAt
	ep.dailyCount = 0
	ep.dailyResetAt = nextQuotaReset(now)
	ep.quotaExhaustedUntil = time.Time{}
	if !ep.blacklistedTill.IsZero() && !ep.blacklistedTill.After(expiredReset) {
		ep.blacklistedTill = time.Time{}
	}
	return true
}

// bumpDailyCount records one Apps Script invocation for an endpoint.
//
// Counts are bumped per HTTP response received (regardless of status), since
// every Apps Script doPost invocation consumes one quota unit even when it
// returns 403 or an HTML error page. Transport-level failures (no response
// reached Apps Script) do not count.
func (c *Client) bumpDailyCount(endpointIdx int) {
	if endpointIdx < 0 {
		return
	}
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if endpointIdx >= len(c.endpoints) {
		return
	}
	ep := &c.endpoints[endpointIdx]
	c.touchDailyWindow(ep, time.Now())
	ep.dailyCount++
}

const (
	// scriptStatsInterval is how often we GET /exec on each deployment to
	// read its self-reported daily count. Every 30 minutes adds ~48
	// invocations/day per deployment — still negligible against the
	// ~20k/day account budget.
	scriptStatsInterval = 30 * time.Minute

	// scriptStatsInitialDelay lets the carrier warm up before the first
	// fetch so startup logs aren't interleaved with stats fetches.
	scriptStatsInitialDelay = 15 * time.Second

	// scriptStatsRequestTimeout caps a single GET. doGet is a fast path
	// (single PropertiesService read) so a tight timeout is fine and
	// keeps a hung Apps Script instance from stalling the loop.
	scriptStatsRequestTimeout = 30 * time.Second

	// scriptStatsMaxBody bounds the response read. The JSON payload is
	// ~50 bytes; 4 KB is a generous ceiling that keeps an unexpected
	// HTML error page from spending memory.
	scriptStatsMaxBody = 4 * 1024
)

// scriptStatsResponse is the JSON the deployed Code.gs returns from doGet.
// Mirrors the shape produced in apps_script/Code.gs.
type scriptStatsResponse struct {
	OK       bool   `json:"ok"`
	Date     string `json:"date"`
	Count    int64  `json:"count"`
	Version  int    `json:"version"`
	Protocol int    `json:"protocol"`
}

// runScriptStatsLoop polls each deployment's doGet endpoint hourly and records
// the script-reported daily count on the corresponding relayEndpoint. The
// recorded value is surfaced in the periodic [stats] line as `script=N`. Runs
// until ctx is canceled.
func (c *Client) runScriptStatsLoop(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(scriptStatsInitialDelay):
	}
	c.pollScriptStats(ctx)

	t := time.NewTicker(scriptStatsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.pollScriptStats(ctx)
		}
	}
}

func (c *Client) pollScriptStats(ctx context.Context) {
	c.endpointMu.Lock()
	urls := make([]string, len(c.endpoints))
	for i := range c.endpoints {
		urls[i] = c.endpoints[i].url
	}
	c.endpointMu.Unlock()

	for i, url := range urls {
		if ctx.Err() != nil {
			return
		}
		c.fetchScriptStats(ctx, i, url)
	}
}

func (c *Client) fetchScriptStats(ctx context.Context, idx int, url string) {
	reqCtx, cancel := context.WithTimeout(ctx, scriptStatsRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	resp, err := c.pickHTTPClient().Do(req)
	if err != nil {
		// Transport error — don't bump the daily count (request never reached
		// Apps Script) and don't log; the next interval will retry.
		return
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, scriptStatsMaxBody))
	// doGet, like doPost, consumes one Apps Script invocation regardless of
	// what we do with the response, so bump the daily counter on any HTTP
	// response we got back.
	c.bumpDailyCount(idx)
	if readErr != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		return
	}
	c.recordScriptStatsFromBody(idx, url, body)
}

// recordScriptStatsFromBody parses a doGet response body and stores the count.
// Split out from fetchScriptStats so the parsing logic is unit-testable without
// standing up an HTTP server.
func (c *Client) recordScriptStatsFromBody(idx int, url string, body []byte) {
	var stats scriptStatsResponse
	trimmed := bytes.TrimSpace(body)
	if err := json.Unmarshal(trimmed, &stats); err != nil || !stats.OK {
		// Most likely the deployed Code.gs is the legacy version whose doGet
		// returns plain text "GooseRelay forwarder OK". Log once per endpoint
		// so the operator knows to redeploy, then stay quiet.
		c.logScriptStatsParseErrorOnce(idx, url, trimmed)
		return
	}
	c.endpointMu.Lock()
	if idx >= 0 && idx < len(c.endpoints) {
		c.endpoints[idx].scriptCount = uint64(stats.Count)
		c.endpoints[idx].scriptCountAt = time.Now()
		// On a successful parse, clear the once-flag so a future regression
		// (operator re-deploys an old version) gets a fresh log line.
		c.endpoints[idx].scriptStatsErrLogged = false
	}
	c.endpointMu.Unlock()
}

func (c *Client) logScriptStatsParseErrorOnce(idx int, url string, body []byte) {
	c.endpointMu.Lock()
	if idx < 0 || idx >= len(c.endpoints) {
		c.endpointMu.Unlock()
		return
	}
	if c.endpoints[idx].scriptStatsErrLogged {
		c.endpointMu.Unlock()
		return
	}
	c.endpoints[idx].scriptStatsErrLogged = true
	c.endpointMu.Unlock()

	snippet := string(body)
	if len(snippet) > 80 {
		snippet = snippet[:80] + "..."
	}
	log.Printf("[carrier] script stats unavailable for %s — redeploy apps_script/Code.gs to enable per-deployment count reporting (got: %q)",
		shortScriptKey(url), snippet)
}
