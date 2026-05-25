package protocol

import "testing"

func TestDownstreamACKPayloadRoundTrip(t *testing.T) {
	payload := EncodeDownstreamACK(12345)

	got, ok := DecodeDownstreamACK(payload)
	if !ok {
		t.Fatal("DecodeDownstreamACK rejected valid payload")
	}
	if got != 12345 {
		t.Fatalf("ack seq = %d, want 12345", got)
	}
}

func TestDecodeDownstreamACKRejectsMalformedPayload(t *testing.T) {
	cases := [][]byte{
		nil,
		[]byte("GACK"),
		[]byte("BADC\x01\x00\x00\x00\x00\x00\x00\x00\x01"),
		[]byte("GACK\x02\x00\x00\x00\x00\x00\x00\x00\x01"),
		append(EncodeDownstreamACK(1), 0),
	}

	for _, tc := range cases {
		if seq, ok := DecodeDownstreamACK(tc); ok {
			t.Fatalf("DecodeDownstreamACK(%q) = %d, true; want rejection", string(tc), seq)
		}
	}
}

func TestVersionProbeCarriesClientRunReset(t *testing.T) {
	payload := EncodeProbePayloadWithOptions("test-client", ProbeOptions{
		ClientInstanceID: "phone-main",
		RunID:            "run-1234",
		ResetPrevious:    true,
	})

	probe, ok := DecodeProbePayload(payload)
	if !ok {
		t.Fatalf("DecodeProbePayload rejected %q", string(payload))
	}
	if probe.ClientVersion != "test-client" || probe.Protocol != ProtocolVersion {
		t.Fatalf("probe version/protocol = %q/%d", probe.ClientVersion, probe.Protocol)
	}
	if probe.ClientInstanceID != "phone-main" {
		t.Fatalf("ClientInstanceID = %q", probe.ClientInstanceID)
	}
	if probe.RunID != "run-1234" {
		t.Fatalf("RunID = %q", probe.RunID)
	}
	if !probe.ResetPrevious {
		t.Fatal("ResetPrevious = false, want true")
	}
}

func TestDecodeProbePayloadRejectsNonProbePayload(t *testing.T) {
	if probe, ok := DecodeProbePayload([]byte("not-a-probe")); ok || probe != nil {
		t.Fatalf("DecodeProbePayload accepted non-probe: %#v", probe)
	}
}
