package carrier

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNextQuotaReset_AdvancesAcrossMidnightPacific(t *testing.T) {
	loc := quotaResetTZ
	// 14:00 PT on a fixed day → next reset is the following midnight PT.
	now := time.Date(2026, 5, 4, 14, 0, 0, 0, loc)
	got := nextQuotaReset(now)
	want := time.Date(2026, 5, 5, 0, 0, 0, 0, loc)
	if !got.Equal(want) {
		t.Fatalf("nextQuotaReset(%v) = %v, want %v", now, got, want)
	}

	// Exactly at midnight PT → next reset must move to the *following* day,
	// not return the same instant (otherwise touchDailyWindow would loop
	// reset → bump → over again on the same boundary).
	atBoundary := time.Date(2026, 5, 5, 0, 0, 0, 0, loc)
	gotBoundary := nextQuotaReset(atBoundary)
	wantBoundary := time.Date(2026, 5, 6, 0, 0, 0, 0, loc)
	if !gotBoundary.Equal(wantBoundary) {
		t.Fatalf("nextQuotaReset at boundary = %v, want %v", gotBoundary, wantBoundary)
	}
}

func TestNextQuotaReset_HandlesPacificDSTTransitions(t *testing.T) {
	if quotaResetTZ.String() != "America/Los_Angeles" {
		t.Skip("system tzdata unavailable; fixed-zone fallback intentionally cannot model DST")
	}
	loc := quotaResetTZ

	springNow := time.Date(2026, 3, 8, 1, 30, 0, 0, loc)
	springReset := nextQuotaReset(springNow)
	wantSpring := time.Date(2026, 3, 9, 0, 0, 0, 0, loc)
	if !springReset.Equal(wantSpring) {
		t.Fatalf("spring reset = %v, want %v", springReset, wantSpring)
	}
	if _, offset := springReset.In(loc).Zone(); offset != -7*3600 {
		t.Fatalf("spring reset offset = %d, want PDT (-7h)", offset)
	}

	fallNow := time.Date(2026, 11, 1, 1, 30, 0, 0, loc)
	fallReset := nextQuotaReset(fallNow)
	wantFall := time.Date(2026, 11, 2, 0, 0, 0, 0, loc)
	if !fallReset.Equal(wantFall) {
		t.Fatalf("fall reset = %v, want %v", fallReset, wantFall)
	}
	if _, offset := fallReset.In(loc).Zone(); offset != -8*3600 {
		t.Fatalf("fall reset offset = %d, want PST (-8h)", offset)
	}
}

func TestBumpDailyCount_RollsOverAtReset(t *testing.T) {
	c := &Client{useFronting: true, endpoints: []relayEndpoint{{url: "u1"}}}

	// First bump initialises the window and increments to 1.
	c.bumpDailyCount(0)
	if got := c.endpoints[0].dailyCount; got != 1 {
		t.Fatalf("after 1 bump dailyCount=%d want 1", got)
	}

	// Force the window to be in the past so the next bump triggers a reset.
	c.endpoints[0].dailyResetAt = time.Now().Add(-time.Minute)
	c.endpoints[0].dailyCount = 42
	c.bumpDailyCount(0)
	if got := c.endpoints[0].dailyCount; got != 1 {
		t.Fatalf("after rollover dailyCount=%d want 1", got)
	}
	if !c.endpoints[0].dailyResetAt.After(time.Now()) {
		t.Fatalf("dailyResetAt should advance to a future instant after rollover")
	}
}

func TestBumpDailyCountForURLIgnoresStaleEndpointAfterReload(t *testing.T) {
	c := &Client{useFronting: true, endpoints: []relayEndpoint{{url: "new-url"}}}

	c.bumpDailyCountForURL(0, "old-url")

	if got := c.endpoints[0].dailyCount; got != 0 {
		t.Fatalf("dailyCount=%d want 0 for stale stats URL", got)
	}
}

func TestBumpDailyCountForLeaseIgnoresStaleEndpointAfterReload(t *testing.T) {
	c := &Client{
		useFronting: true,
		endpoints:   []relayEndpoint{{url: "old-url", bucket: "old"}},
		endpointGen: 1,
	}
	lease := endpointLease{idx: 0, url: "old-url", bucket: "old", generation: 1, check: true}

	c.endpointMu.Lock()
	c.endpoints = []relayEndpoint{{url: "new-url", bucket: "new"}}
	c.endpointGen = 2
	c.endpointMu.Unlock()

	c.bumpDailyCountForLease(lease)

	if got := c.endpoints[0].dailyCount; got != 0 {
		t.Fatalf("dailyCount=%d want 0 for stale endpoint lease", got)
	}
}

func TestEndpointFailureLeaseIgnoresStaleEndpointAfterReload(t *testing.T) {
	c := &Client{
		endpoints:                []relayEndpoint{{url: "old-url", bucket: "old"}},
		endpointGen:              1,
		endpointBlacklistMaxTTL:  time.Hour,
		endpointBlacklistBaseTTL: time.Second,
	}
	lease := endpointLease{idx: 0, url: "old-url", bucket: "old", generation: 1, check: true}

	c.endpointMu.Lock()
	c.endpoints = []relayEndpoint{{url: "new-url", bucket: "new"}}
	c.endpointGen = 2
	c.endpointMu.Unlock()

	c.recordEndpointFailureReasonLease(lease, endpointFailureHTTPError)
	c.markEndpointFailureLease(lease)

	if got := c.endpoints[0].statsFail; got != 0 {
		t.Fatalf("statsFail=%d want 0 for stale endpoint lease", got)
	}
	if got := c.endpoints[0].failureReasons[endpointFailureHTTPError]; got != 0 {
		t.Fatalf("failure reason count=%d want 0 for stale endpoint lease", got)
	}
}

func TestDiagnoseFailureIgnoresStaleEndpointLeaseAfterReload(t *testing.T) {
	c := &Client{
		endpoints:                []relayEndpoint{{url: "old-url", bucket: "old"}},
		endpointGen:              1,
		endpointBlacklistMaxTTL:  time.Hour,
		endpointBlacklistBaseTTL: time.Second,
	}
	lease := endpointLease{idx: 0, url: "old-url", bucket: "old", generation: 1, check: true}

	c.endpointMu.Lock()
	c.endpoints = []relayEndpoint{{url: "new-url", bucket: "new"}}
	c.endpointGen = 2
	c.endpointMu.Unlock()

	c.markEndpointDiagnoseFailure(lease, diagnoseError(relayErrorDailyQuota, "quota exhausted"))

	if got := c.endpoints[0].statsFail; got != 0 {
		t.Fatalf("statsFail=%d want 0 for stale diagnose endpoint lease", got)
	}
	if !c.endpoints[0].quotaExhaustedUntil.IsZero() {
		t.Fatalf("quotaExhaustedUntil=%v want zero for stale diagnose endpoint lease", c.endpoints[0].quotaExhaustedUntil)
	}
	if got := c.endpoints[0].failureReasons[endpointFailureQuota]; got != 0 {
		t.Fatalf("quota failure reason count=%d want 0 for stale diagnose endpoint lease", got)
	}
}

func TestSaveQuotaStateWritesValidAtomicFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota-state.json")
	resetAt := time.Now().Add(time.Hour).Truncate(time.Second)
	c := &Client{
		quotaStatePath: path,
		endpoints: []relayEndpoint{{
			url:                 "url-a",
			account:             "acct-a",
			bucket:              "acct-a",
			quotaExhaustedUntil: resetAt,
		}},
	}

	if err := c.saveQuotaState(); err != nil {
		t.Fatalf("saveQuotaState: %v", err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read quota state: %v", err)
	}
	var state quotaStateFile
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatalf("quota state is not valid JSON: %v\n%s", err, body)
	}
	if len(state.Entries) != 1 || state.Entries[0].Key != "acct:acct-a" {
		t.Fatalf("quota entries = %+v, want one acct:acct-a entry", state.Entries)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".quota-state.json.tmp-*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("atomic temp files left behind: %v", matches)
	}
}

func TestSaveQuotaStateDoesNotPersistRawUnlabeledEndpointURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota-state.json")
	rawURL := "https://script.google.com/macros/s/SECRET_DEPLOYMENT/exec"
	c := &Client{
		quotaStatePath: path,
		endpoints: []relayEndpoint{{
			url:                 rawURL,
			bucket:              "url:" + rawURL,
			quotaExhaustedUntil: time.Now().Add(time.Hour),
		}},
	}

	if err := c.saveQuotaState(); err != nil {
		t.Fatalf("saveQuotaState: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read quota state: %v", err)
	}
	text := string(body)
	if strings.Contains(text, rawURL) || strings.Contains(text, "SECRET_DEPLOYMENT") {
		t.Fatalf("quota state leaked raw endpoint URL:\n%s", text)
	}
	if !strings.Contains(text, `"key": "urlsha256:`) {
		t.Fatalf("quota state missing hashed unlabeled endpoint key:\n%s", text)
	}
}

func TestTouchDailyWindowClearsQuotaBlacklistAtReset(t *testing.T) {
	loc := quotaResetTZ
	reset := time.Date(2026, 5, 15, 0, 0, 0, 0, loc)
	c := &Client{endpoints: []relayEndpoint{{
		dailyCount:          123,
		dailyResetAt:        reset,
		quotaExhaustedUntil: reset,
		blacklistedTill:     reset,
	}}}

	if !c.touchDailyWindow(&c.endpoints[0], reset.Add(time.Second)) {
		t.Fatal("expected rollover")
	}
	if !c.endpoints[0].blacklistedTill.IsZero() {
		t.Fatalf("blacklistedTill = %v, want cleared on quota reset", c.endpoints[0].blacklistedTill)
	}
}

func TestTouchDailyWindowKeepsFutureNonQuotaBlacklist(t *testing.T) {
	loc := quotaResetTZ
	reset := time.Date(2026, 5, 15, 0, 0, 0, 0, loc)
	futureBlacklist := reset.Add(30 * time.Minute)
	c := &Client{endpoints: []relayEndpoint{{
		dailyCount:          123,
		dailyResetAt:        reset,
		quotaExhaustedUntil: reset,
		blacklistedTill:     futureBlacklist,
	}}}

	if !c.touchDailyWindow(&c.endpoints[0], reset.Add(time.Second)) {
		t.Fatal("expected rollover")
	}
	if !c.endpoints[0].blacklistedTill.Equal(futureBlacklist) {
		t.Fatalf("blacklistedTill = %v, want future non-quota blacklist preserved", c.endpoints[0].blacklistedTill)
	}
}

func TestEndpointUnavailableKeepsFutureBlacklistAfterDailyRollover(t *testing.T) {
	loc := quotaResetTZ
	reset := time.Date(2026, 5, 15, 0, 0, 0, 0, loc)
	now := reset.Add(time.Second)
	futureBlacklist := reset.Add(30 * time.Minute)
	c := &Client{}
	ep := relayEndpoint{
		dailyCount:          123,
		dailyResetAt:        reset,
		quotaExhaustedUntil: reset,
		blacklistedTill:     futureBlacklist,
	}

	if !c.endpointUnavailableLocked(&ep, now) {
		t.Fatal("endpoint became available for one poll even though a future blacklist survived rollover")
	}
}

func TestRecordScriptStatsFromBody_ParsesValidJSON(t *testing.T) {
	c := &Client{endpoints: []relayEndpoint{{url: "u1"}}}
	body := []byte(`{"ok":true,"date":"2026-05-04","count":4321,"counting_enabled":true}`)
	c.recordScriptStatsFromBody(0, "u1", body)
	if got := c.endpoints[0].scriptCount; got != 4321 {
		t.Fatalf("scriptCount=%d want 4321", got)
	}
	if c.endpoints[0].scriptCountAt.IsZero() {
		t.Fatalf("scriptCountAt should be set after a successful parse")
	}
}

func TestRecordScriptStatsFromBodyIgnoresStaleEndpointAfterReload(t *testing.T) {
	c := &Client{endpoints: []relayEndpoint{{url: "new-url"}}}
	body := []byte(`{"ok":true,"date":"2026-05-04","count":4321,"counting_enabled":true}`)

	c.recordScriptStatsFromBody(0, "old-url", body)

	if got := c.endpoints[0].scriptCount; got != 0 {
		t.Fatalf("scriptCount=%d want 0 for stale stats URL", got)
	}
	if !c.endpoints[0].scriptCountAt.IsZero() {
		t.Fatal("scriptCountAt should remain unset for stale stats URL")
	}
}

func TestRecordScriptStatsFromBody_IgnoresDisabledInvocationCounting(t *testing.T) {
	now := time.Now()
	c := &Client{endpoints: []relayEndpoint{{
		url:           "u1",
		scriptCount:   987,
		scriptCountAt: now,
	}}}
	body := []byte(`{"ok":true,"date":"2026-05-04","count":0,"counting_enabled":false,"version":1,"protocol":1}`)

	c.recordScriptStatsFromBody(0, "u1", body)

	if got := c.endpoints[0].scriptCount; got != 0 {
		t.Fatalf("scriptCount=%d want 0 when script counting is disabled", got)
	}
	if !c.endpoints[0].scriptCountAt.IsZero() {
		t.Fatal("scriptCountAt should be cleared when script counting is disabled")
	}
}

func TestRecordScriptStatsFromBody_MissingCountingEnabledClearsUnknownCount(t *testing.T) {
	now := time.Now()
	c := &Client{endpoints: []relayEndpoint{{
		url:           "u1",
		scriptCount:   987,
		scriptCountAt: now,
	}}}
	body := []byte(`{"ok":true,"date":"2026-05-04","count":4321,"version":1,"protocol":1}`)

	c.recordScriptStatsFromBody(0, "u1", body)

	if got := c.endpoints[0].scriptCount; got != 0 {
		t.Fatalf("scriptCount=%d want 0 when counting_enabled is missing", got)
	}
	if !c.endpoints[0].scriptCountAt.IsZero() {
		t.Fatal("scriptCountAt should be cleared when counting_enabled is missing")
	}
}

func TestRecordScriptStatsFromBody_LegacyTextResponse(t *testing.T) {
	// Old apps_script/Code.gs returns "GooseRelay forwarder OK" from doGet.
	// We must not panic, must not record a count, and must flag the once-log.
	c := &Client{endpoints: []relayEndpoint{{url: "u1"}}}
	c.recordScriptStatsFromBody(0, "u1", []byte("GooseRelay forwarder OK"))
	if !c.endpoints[0].scriptCountAt.IsZero() {
		t.Fatalf("scriptCountAt should remain zero on a non-JSON body")
	}
	if !c.endpoints[0].scriptStatsErrLogged {
		t.Fatalf("scriptStatsErrLogged should be set so future hours don't re-log")
	}
}

func TestAccountStatsLine_DedupesSharedScriptCount(t *testing.T) {
	// Two deployments of one Apps Script project under account A: PropertiesService
	// is per-project so both report the same scriptCount. Summing would
	// double-count the project's true count. A third deployment under account B
	// (different project, different count) should still be summed normally.
	now := time.Now()
	c := &Client{endpoints: []relayEndpoint{
		{url: "u1", account: "A", dailyCount: 30, scriptCount: 1674, scriptCountAt: now, dailyResetAt: now.Add(time.Hour)},
		{url: "u2", account: "A", dailyCount: 30, scriptCount: 1674, scriptCountAt: now, dailyResetAt: now.Add(time.Hour)},
		{url: "u3", account: "B", dailyCount: 65, scriptCount: 1503, scriptCountAt: now, dailyResetAt: now.Add(time.Hour)},
	}}

	got := c.accountStatsLine()

	// A's two deployments share count 1674 → reported once, not 1674+1674=3348.
	// today still sums normally (per-deployment client-side counter).
	wantA := "A today=60 script=1674"
	wantB := "B today=65 script=1503"
	for _, want := range []string{wantA, wantB} {
		if !strings.Contains(got, want) {
			t.Fatalf("accountStatsLine() = %q, missing %q", got, want)
		}
	}
	if strings.Contains(got, "script=3348") {
		t.Fatalf("accountStatsLine() = %q, double-counted shared scriptCount", got)
	}
	items := c.accountStatsItems()
	if len(items) != 2 {
		t.Fatalf("accountStatsItems len = %d, want 2", len(items))
	}
	if items[0]["account"] != "A" || items[0]["today"] != uint64(60) || items[0]["script"] != uint64(1674) {
		t.Fatalf("accountStatsItems[0] = %#v, want account A today=60 script=1674", items[0])
	}
	if items[1]["account"] != "B" || items[1]["today"] != uint64(65) || items[1]["script"] != uint64(1503) {
		t.Fatalf("accountStatsItems[1] = %#v, want account B today=65 script=1503", items[1])
	}
}

func TestAccountStatsLine_SumsDistinctProjectsUnderOneAccount(t *testing.T) {
	// Two distinct Apps Script projects under one account: distinct
	// scriptCount values, so they should sum.
	now := time.Now()
	c := &Client{endpoints: []relayEndpoint{
		{url: "u1", account: "A", dailyCount: 10, scriptCount: 100, scriptCountAt: now, dailyResetAt: now.Add(time.Hour)},
		{url: "u2", account: "A", dailyCount: 20, scriptCount: 250, scriptCountAt: now, dailyResetAt: now.Add(time.Hour)},
	}}

	got := c.accountStatsLine()
	want := "A today=30 script=350"
	if !strings.Contains(got, want) {
		t.Fatalf("accountStatsLine() = %q, want substring %q", got, want)
	}
}

func TestClassifyRelayErrorBodyKind_DetectsLocalizedUrlFetchDailyQuota(t *testing.T) {
	body := []byte("Exception: \u0633\u0631\u0648\u06cc\u0633 \u062f\u0631 \u0637\u0648\u0644 \u06cc\u06a9 \u0631\u0648\u0632 \u0628\u0647 \u062f\u0641\u0639\u0627\u062a \u0632\u06cc\u0627\u062f \u0641\u0631\u0627\u062e\u0648\u0627\u0646\u062f\u0647 \u0634\u062f\u0647 \u0627\u0633\u062a:urlfetch.")

	reason, kind := classifyRelayErrorBodyKind(body)

	if kind != relayErrorDailyQuota {
		t.Fatalf("kind = %v reason = %q, want relayErrorDailyQuota", kind, reason)
	}
}

func TestRecordScriptStatsFromBody_RecoveryAfterRedeploy(t *testing.T) {
	// Simulate operator redeploying: first poll returns legacy text (logs once),
	// next poll returns JSON. We should record the count AND clear the
	// once-flag so a future regression would log a fresh warning.
	c := &Client{endpoints: []relayEndpoint{{url: "u1"}}}
	c.recordScriptStatsFromBody(0, "u1", []byte("GooseRelay forwarder OK"))
	if !c.endpoints[0].scriptStatsErrLogged {
		t.Fatalf("first call should set scriptStatsErrLogged")
	}
	c.recordScriptStatsFromBody(0, "u1", []byte(`{"ok":true,"date":"2026-05-04","count":7,"counting_enabled":true}`))
	if c.endpoints[0].scriptStatsErrLogged {
		t.Fatalf("scriptStatsErrLogged should clear after a successful parse")
	}
	if c.endpoints[0].scriptCount != 7 {
		t.Fatalf("scriptCount=%d want 7", c.endpoints[0].scriptCount)
	}
}
