package apps_script

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestCodeGSOmitsDeploymentVariantMetadata(t *testing.T) {
	body, err := os.ReadFile("Code.gs")
	if err != nil {
		t.Fatalf("read Code.gs: %v", err)
	}
	text := string(body)
	if strings.Contains(text, "SCRIPT_VARIANT_ID") {
		t.Fatal("Code.gs should not define SCRIPT_VARIANT_ID")
	}
	if strings.Contains(text, "variant_id") {
		t.Fatal("doGet metadata should not include variant_id")
	}
}

func TestCodeGSLoopGuardCoversAppsScriptRelayURLs(t *testing.T) {
	body, err := os.ReadFile("Code.gs")
	if err != nil {
		t.Fatalf("read Code.gs: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"GAS_RELAY_LOOP_RE",
		"script\\.google\\.com",
		"script\\.googleusercontent\\.com",
		"relay_loop_detected",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Code.gs loop guard missing %q", want)
		}
	}
	if !regexp.MustCompile(`isAppsScriptRelayURL_\s*\(\s*RELAY_URLS\[i\]\s*\)`).MatchString(text) {
		t.Fatal("doPost should check every RELAY_URLS entry before forwarding")
	}
}

func TestCodeGSPayloadAndForwardingSafetyKnobsStayPresent(t *testing.T) {
	body, err := os.ReadFile("Code.gs")
	if err != nil {
		t.Fatalf("read Code.gs: %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"MAX_TUNNEL_PAYLOAD_CHARS",
		"text.length > MAX_TUNNEL_PAYLOAD_CHARS",
		"FORWARD_TIMEOUT_SECONDS",
		"timeoutSeconds: FORWARD_TIMEOUT_SECONDS",
		"followRedirects: false",
		"muteHttpExceptions: true",
		"throw new Error(lastError)",
		"max_payload_chars: MAX_TUNNEL_PAYLOAD_CHARS",
		"timeout_seconds: FORWARD_TIMEOUT_SECONDS",
		"version: FORWARDER_VERSION",
		"protocol: PROTOCOL_VERSION",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Code.gs safety/metadata check missing %q", want)
		}
	}
}
