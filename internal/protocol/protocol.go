package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
)

const (
	ProtocolVersion = 1
	ProbePrefix     = "goose_version_probe:v1"
	// FeatureDownstreamReplayV1 is advertised by servers that can consume
	// downstream ACK control frames and replay sent-but-unacked downstream
	// frames for POST transports.
	FeatureDownstreamReplayV1 = "downstream_replay_v1"
	// FeatureBinaryBatchV1 is advertised by servers that accept authenticated
	// binary relay batches on /tunnel. Direct POST clients start with the text
	// envelope for compatibility and switch to binary only after seeing this.
	FeatureBinaryBatchV1 = "binary_batch_v1"
	// FeatureClientRunResetV1 is advertised by servers that understand stable
	// client instance IDs in version probes and can close stale sessions from a
	// previous process run of the same client instance.
	FeatureClientRunResetV1 = "client_run_reset_v1"

	MaxFramePayload = 256 * 1024

	MaxDrainFramesPerBatch     = 48
	BusySessionThreshold       = 24
	MaxDrainFramesPerBatchBusy = 144
	// DefaultMaxDrainFramesPerSession limits how much one hot downstream TCP
	// session can take from a single server response. Operators can raise this
	// for single-file download tests, but very high values reduce fairness for
	// browsing/video sessions sharing the same Apps Script lane.
	DefaultMaxDrainFramesPerSession = 8
	MaxDrainFramesPerSession        = 64

	MaxRequestBytesPreEncode = 8 * 1024 * 1024
	// DefaultMaxResponseBytesPreEncode is the balanced Apps Script downstream
	// response cap after the startup ramp. Keep MaxResponseBytesPreEncode as
	// the explicit upper ceiling for stable/direct links.
	DefaultMaxResponseBytesPreEncode = 6 * 1024 * 1024
	MaxResponseBytesPreEncode        = 22 * 1024 * 1024
	// InitialResponseBytesPreEncode caps the first downstream response for a
	// newly-opened session. Apps Script buffers full HTTP responses, so keeping
	// the first file-download/header burst small improves browser-visible start
	// time without reducing later bulk throughput.
	InitialResponseBytesPreEncode = 512 * 1024
	// SecondResponseBytesPreEncode ramps a new session after the first small
	// response while avoiding an immediate jump to the full bulk cap. Keep the
	// default conservative for Apps Script/mobile links; operators can raise it
	// with second_response_bytes_pre_encode when the path is stable.
	SecondResponseBytesPreEncode = 1024 * 1024
	// DownstreamReplayPerSessionBytes is the default per-session replay cap.
	// Keep the default response cap below this so replay can retain at least
	// one full sent response without immediately aborting the session.
	DownstreamReplayPerSessionBytes = 8 * 1024 * 1024
	// MaxRequestBodyBytes bounds the HTTP request body accepted by the VPS.
	// It must be larger than MaxRequestBytesPreEncode because Apps Script mode
	// base64-expands the sealed envelope by roughly 4/3 before it reaches
	// /tunnel, but it is intentionally low enough to keep unauthenticated
	// request reads from pinning excessive memory.
	MaxRequestBodyBytes = 12 * 1024 * 1024

	DefaultWorkersPerEndpoint       = 3
	DefaultPollIdleSleepMs          = 5
	DefaultPollTimeoutMs            = 300000
	DefaultIdlePollMaxBuckets       = 2
	DefaultEndpointBlacklistBaseMs  = 3000
	DefaultEndpointBlacklistMaxMs   = 60 * 60 * 1000
	DefaultEndpointOutageGraceMs    = 300000
	DefaultActiveDrainWindowMs      = 150
	DefaultLongPollWindowMs         = 6000
	DefaultUpstreamDialTimeoutMs    = 15000
	DefaultCoalesceWindowMs         = 0
	DefaultCoalesceWindowBusyMs     = 0
	DefaultStreamConnectTimeoutMs   = 5000
	DefaultStreamPingIntervalMs     = 20000
	DefaultStreamReconnectBackoffMs = 1000
	DefaultMaxServerSessions        = 4096
	DefaultTxBufferBudgetBytes      = 64 * 1024 * 1024
	LatencyPollIdleSleepMs          = 5
	LatencyActiveDrainWindowMs      = 150
	LatencyLongPollWindowMs         = 6000
	LatencyUpstreamDialTimeoutMs    = 8000
	ThroughputCoalesceStepMs        = 25
	ThroughputIdleSlotsPerBucket    = 2
	ThroughputCoalesceWindowMs      = 35
	ThroughputCoalesceWindowBusyMs  = 15
)

const downstreamACKMagic = "GACK"

const (
	downstreamACKVersion = 1
	downstreamACKLen     = len(downstreamACKMagic) + 1 + 8
)

type VersionInfo struct {
	OK              bool     `json:"ok"`
	Protocol        int      `json:"protocol"`
	ServerVersion   string   `json:"server_version"`
	MaxFramePayload int      `json:"max_frame_payload"`
	Features        []string `json:"features"`
}

type VersionProbe struct {
	Type             string `json:"type"`
	ClientVersion    string `json:"client_version"`
	Protocol         int    `json:"protocol"`
	ClientInstanceID string `json:"client_instance_id,omitempty"`
	RunID            string `json:"run_id,omitempty"`
	ResetPrevious    bool   `json:"reset_previous,omitempty"`
}

type ProbeOptions struct {
	ClientInstanceID string
	RunID            string
	ResetPrevious    bool
}

func EncodeProbePayload(clientVersion string) []byte {
	return EncodeProbePayloadWithOptions(clientVersion, ProbeOptions{})
}

func EncodeProbePayloadWithOptions(clientVersion string, opts ProbeOptions) []byte {
	probe := VersionProbe{
		Type:             "version_probe",
		ClientVersion:    clientVersion,
		Protocol:         ProtocolVersion,
		ClientInstanceID: opts.ClientInstanceID,
		RunID:            opts.RunID,
		ResetPrevious:    opts.ResetPrevious,
	}
	b, _ := json.Marshal(probe)
	return append([]byte(ProbePrefix+"|"), b...)
}

func IsProbePayload(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte(ProbePrefix+"|")) || bytes.Equal(payload, []byte(ProbePrefix))
}

func DecodeProbePayload(payload []byte) (*VersionProbe, bool) {
	payload = bytes.TrimSpace(payload)
	prefix := []byte(ProbePrefix + "|")
	if bytes.Equal(payload, []byte(ProbePrefix)) {
		return &VersionProbe{Type: "version_probe", Protocol: ProtocolVersion}, true
	}
	if !bytes.HasPrefix(payload, prefix) {
		return nil, false
	}
	var probe VersionProbe
	if err := json.Unmarshal(payload[len(prefix):], &probe); err != nil {
		return nil, false
	}
	if probe.Type != "" && probe.Type != "version_probe" {
		return nil, false
	}
	if probe.Protocol == 0 {
		probe.Protocol = ProtocolVersion
	}
	return &probe, true
}

func DecodeVersionInfo(payload []byte) (*VersionInfo, error) {
	var info VersionInfo
	if err := json.Unmarshal(bytes.TrimSpace(payload), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

func EncodeVersionInfo(serverVersion string, maxFramePayload int, features []string) ([]byte, error) {
	info := VersionInfo{
		OK:              true,
		Protocol:        ProtocolVersion,
		ServerVersion:   serverVersion,
		MaxFramePayload: maxFramePayload,
		Features:        features,
	}
	return json.Marshal(info)
}

func HasFeature(features []string, feature string) bool {
	for _, f := range features {
		if f == feature {
			return true
		}
	}
	return false
}

// EncodeDownstreamACK builds the payload carried by a FlagACK control frame
// when downstream replay is negotiated. ackNextSeq means all downstream frames
// with Seq < ackNextSeq have been accepted in order by the client.
func EncodeDownstreamACK(ackNextSeq uint64) []byte {
	out := make([]byte, downstreamACKLen)
	copy(out[:4], downstreamACKMagic)
	out[4] = downstreamACKVersion
	binary.BigEndian.PutUint64(out[5:], ackNextSeq)
	return out
}

func DecodeDownstreamACK(payload []byte) (uint64, bool) {
	if len(payload) != downstreamACKLen {
		return 0, false
	}
	if !bytes.Equal(payload[:4], []byte(downstreamACKMagic)) || payload[4] != downstreamACKVersion {
		return 0, false
	}
	return binary.BigEndian.Uint64(payload[5:]), true
}
