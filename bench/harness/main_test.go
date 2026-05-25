package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseImpairmentProfile(t *testing.T) {
	prof, err := parseImpairmentProfile("mobile")
	if err != nil {
		t.Fatalf("parse mobile: %v", err)
	}
	if !prof.Enabled() {
		t.Fatal("mobile profile should be enabled")
	}
	if prof.BaseDelay <= 0 || prof.JitterStep <= 0 || prof.TransientErrorEvery != 0 || prof.RateLimitEvery != 0 {
		t.Fatalf("mobile profile missing impairment knobs: %#v", prof)
	}
	lossy, err := parseImpairmentProfile("lossy")
	if err != nil {
		t.Fatalf("parse lossy: %v", err)
	}
	if lossy.TransientErrorEvery == 0 {
		t.Fatalf("lossy profile should inject transient failures: %#v", lossy)
	}
	quota, err := parseImpairmentProfile("quota")
	if err != nil {
		t.Fatalf("parse quota: %v", err)
	}
	if quota.RateLimitEvery == 0 || quota.DailyQuotaEvery == 0 {
		t.Fatalf("quota profile should inject quota/rate-limit failures: %#v", quota)
	}

	none, err := parseImpairmentProfile("")
	if err != nil {
		t.Fatalf("parse empty: %v", err)
	}
	if none.Enabled() {
		t.Fatalf("empty profile enabled: %#v", none)
	}

	if _, err := parseImpairmentProfile("mystery"); err == nil {
		t.Fatal("unknown profile should fail")
	}
}

func TestBenchmarkMetadataRecordsTransportAndImpairment(t *testing.T) {
	prof, err := parseImpairmentProfile("mobile")
	if err != nil {
		t.Fatalf("parse impairment: %v", err)
	}
	meta := benchmarkMetadataFor("direct_post", prof)
	if meta.Transport != "direct_post" {
		t.Fatalf("transport = %q, want direct_post", meta.Transport)
	}
	if meta.Impairment != "mobile" {
		t.Fatalf("impairment = %q, want mobile", meta.Impairment)
	}
	if meta.Config["auto_tune"] != false || meta.Config["loopback_profile"] != true {
		t.Fatalf("metadata config missing stable benchmark knobs: %#v", meta.Config)
	}

	none := benchmarkMetadataFor("direct_stream", impairmentProfile{})
	if none.Impairment != "none" {
		t.Fatalf("empty impairment = %q, want none", none.Impairment)
	}
}

func TestImpairmentProxyInjectsDeterministicFailures(t *testing.T) {
	upstreamHits := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	prof := impairmentProfile{
		Name:                "test",
		TransientErrorEvery: 2,
		RateLimitEvery:      3,
		DailyQuotaEvery:     5,
	}
	proxy := httptest.NewServer(newImpairmentHandler(upstream.URL, prof))
	defer proxy.Close()

	want := []struct {
		status int
		body   string
	}{
		{http.StatusOK, "ok"},
		{http.StatusBadGateway, "simulated dropped response"},
		{http.StatusTooManyRequests, "short time"},
		{http.StatusBadGateway, "simulated dropped response"},
		{http.StatusForbidden, "too many times"},
	}
	for i, tc := range want {
		resp, err := http.Post(proxy.URL+"/tunnel", "text/plain", strings.NewReader("batch"))
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.status || !strings.Contains(string(body), tc.body) {
			t.Fatalf("request %d status/body = %d %q, want %d containing %q", i+1, resp.StatusCode, string(body), tc.status, tc.body)
		}
	}
	if upstreamHits != 1 {
		t.Fatalf("upstream hits = %d, want only the first non-impaired request forwarded", upstreamHits)
	}
}

func TestImpairmentDelayIsDeterministic(t *testing.T) {
	prof := impairmentProfile{
		Name:        "test",
		BaseDelay:   100 * time.Millisecond,
		JitterStep:  25 * time.Millisecond,
		JitterSlots: 4,
	}
	got := []time.Duration{
		prof.DelayForRequest(1),
		prof.DelayForRequest(2),
		prof.DelayForRequest(3),
		prof.DelayForRequest(4),
		prof.DelayForRequest(5),
	}
	want := []time.Duration{
		125 * time.Millisecond,
		150 * time.Millisecond,
		175 * time.Millisecond,
		100 * time.Millisecond,
		125 * time.Millisecond,
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delay[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}
