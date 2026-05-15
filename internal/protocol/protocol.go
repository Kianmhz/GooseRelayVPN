package protocol

import (
	"bytes"
	"encoding/json"
)

const (
	ProtocolVersion = 1
	ProbePrefix     = "goose_version_probe:v1"

	MaxFramePayload = 256 * 1024

	MaxDrainFramesPerBatch     = 48
	BusySessionThreshold       = 24
	MaxDrainFramesPerBatchBusy = 144

	MaxRequestBytesPreEncode  = 8 * 1024 * 1024
	MaxResponseBytesPreEncode = 22 * 1024 * 1024
	// MaxRequestBodyBytes bounds the HTTP request body accepted by the VPS.
	// It must be larger than MaxRequestBytesPreEncode because Apps Script mode
	// base64-expands the sealed envelope by roughly 4/3 before it reaches /tunnel.
	MaxRequestBodyBytes = 12 * 1024 * 1024

	DefaultWorkersPerEndpoint       = 4
	DefaultPollIdleSleepMs          = 5
	DefaultEndpointBlacklistBaseMs  = 3000
	DefaultEndpointBlacklistMaxMs   = 60 * 60 * 1000
	DefaultEndpointOutageGraceMs    = 60000
	DefaultActiveDrainWindowMs      = 150
	DefaultLongPollWindowMs         = 6000
	DefaultUpstreamDialTimeoutMs    = 15000
	DefaultCoalesceWindowMs         = 0
	DefaultCoalesceWindowBusyMs     = 0
	DefaultStreamConnectTimeoutMs   = 5000
	DefaultStreamPingIntervalMs     = 20000
	DefaultStreamReconnectBackoffMs = 1000
	DefaultMaxServerSessions        = 4096
	LatencyPollIdleSleepMs          = 5
	LatencyActiveDrainWindowMs      = 150
	LatencyLongPollWindowMs         = 6000
	LatencyUpstreamDialTimeoutMs    = 8000
	ThroughputCoalesceStepMs        = 25
	ThroughputIdleSlotsPerBucket    = 2
	ThroughputCoalesceWindowMs      = 35
	ThroughputCoalesceWindowBusyMs  = 15
)

type VersionInfo struct {
	OK              bool     `json:"ok"`
	Protocol        int      `json:"protocol"`
	ServerVersion   string   `json:"server_version"`
	MaxFramePayload int      `json:"max_frame_payload"`
	Features        []string `json:"features"`
}

type VersionProbe struct {
	Type          string `json:"type"`
	ClientVersion string `json:"client_version"`
	Protocol      int    `json:"protocol"`
}

func EncodeProbePayload(clientVersion string) []byte {
	probe := VersionProbe{
		Type:          "version_probe",
		ClientVersion: clientVersion,
		Protocol:      ProtocolVersion,
	}
	b, _ := json.Marshal(probe)
	return append([]byte(ProbePrefix+"|"), b...)
}

func IsProbePayload(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte(ProbePrefix+"|")) || bytes.Equal(payload, []byte(ProbePrefix))
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
