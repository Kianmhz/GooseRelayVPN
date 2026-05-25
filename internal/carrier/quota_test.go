package carrier

import (
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

func TestBumpDailyCount_RollsOverAtReset(t *testing.T) {
	c := &Client{endpoints: []relayEndpoint{{url: "u1"}}}

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

func TestRecordScriptStatsFromBody_ParsesValidJSON(t *testing.T) {
	c := &Client{endpoints: []relayEndpoint{{url: "u1"}}}
	body := []byte(`{"ok":true,"date":"2026-05-04","count":4321}`)
	c.recordScriptStatsFromBody(0, "u1", body)
	if got := c.endpoints[0].scriptCount; got != 4321 {
		t.Fatalf("scriptCount=%d want 4321", got)
	}
	if c.endpoints[0].scriptCountAt.IsZero() {
		t.Fatalf("scriptCountAt should be set after a successful parse")
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

func TestRecordScriptStatsFromBody_RecoveryAfterRedeploy(t *testing.T) {
	// Simulate operator redeploying: first poll returns legacy text (logs once),
	// next poll returns JSON. We should record the count AND clear the
	// once-flag so a future regression would log a fresh warning.
	c := &Client{endpoints: []relayEndpoint{{url: "u1"}}}
	c.recordScriptStatsFromBody(0, "u1", []byte("GooseRelay forwarder OK"))
	if !c.endpoints[0].scriptStatsErrLogged {
		t.Fatalf("first call should set scriptStatsErrLogged")
	}
	c.recordScriptStatsFromBody(0, "u1", []byte(`{"ok":true,"date":"2026-05-04","count":7}`))
	if c.endpoints[0].scriptStatsErrLogged {
		t.Fatalf("scriptStatsErrLogged should clear after a successful parse")
	}
	if c.endpoints[0].scriptCount != 7 {
		t.Fatalf("scriptCount=%d want 7", c.endpoints[0].scriptCount)
	}
}

func TestMarkEndpointQuotaExhaustedScopesToAccountAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quota.json")
	now := time.Now()
	c := &Client{
		quotaStatePath: path,
		endpoints: []relayEndpoint{
			{url: "u1", account: "A", dailyResetAt: now.Add(time.Hour)},
			{url: "u2", account: "A", dailyResetAt: now.Add(time.Hour)},
			{url: "u3", account: "B", dailyResetAt: now.Add(time.Hour)},
		},
	}

	c.markEndpointQuotaExhausted(0)

	if !c.endpoints[0].quotaExhaustedUntil.After(now) {
		t.Fatalf("endpoint 0 was not quota-quarantined")
	}
	if !c.endpoints[1].quotaExhaustedUntil.Equal(c.endpoints[0].quotaExhaustedUntil) {
		t.Fatalf("same-account endpoint was not quarantined with endpoint 0")
	}
	if !c.endpoints[2].quotaExhaustedUntil.IsZero() {
		t.Fatalf("different account was quarantined: %v", c.endpoints[2].quotaExhaustedUntil)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("quota state was not persisted: %v", err)
	}

	restored := &Client{
		endpoints: []relayEndpoint{
			{url: "u1", account: "A"},
			{url: "u2", account: "A"},
			{url: "u3", account: "B"},
		},
	}
	if err := restored.loadQuotaState(path); err != nil {
		t.Fatalf("loadQuotaState: %v", err)
	}
	if !restored.endpoints[0].blacklistedTill.After(now) || !restored.endpoints[1].blacklistedTill.After(now) {
		t.Fatalf("restored same-account quota quarantine = %#v", restored.endpoints)
	}
	if !restored.endpoints[2].blacklistedTill.IsZero() {
		t.Fatalf("restored different account blacklist = %v", restored.endpoints[2].blacklistedTill)
	}
}
