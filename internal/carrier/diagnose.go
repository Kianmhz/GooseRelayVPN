package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
)

// Diagnose performs a one-shot end-to-end health check against the first
// configured relay endpoint and returns nil if everything is wired up
// correctly. On failure it returns an error whose text describes the most
// likely root cause in user-actionable language.
//
// The two probes:
//
//  1. GET <scriptURL>/exec — Apps Script's doGet returns "GooseRelay
//     forwarder OK". If we get HTML or 404 the deployment is wrong or
//     not public.
//  2. POST an encrypted probe batch — server should round-trip a valid
//     encrypted reply with version info. 204 No Content means our key did not decrypt
//     (key mismatch); HTTP 5xx with HTML means Apps Script could not
//     reach the VPS.
func (c *Client) Diagnose(ctx context.Context) error {
	c.endpointMu.Lock()
	if len(c.endpoints) == 0 {
		c.endpointMu.Unlock()
		return fmt.Errorf("no relay endpoints configured")
	}
	scriptURL := c.endpoints[0].url
	c.endpointMu.Unlock()

	if c.binaryDirect {
		return c.diagnosePost(ctx, scriptURL)
	}

	// --- Probe 1: GET the deployment to confirm it is live and public. ---
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
	if err != nil {
		return fmt.Errorf("building GET request: %w", err)
	}
	getResp, err := c.pickHTTPClient().Do(getReq)
	if err != nil {
		return fmt.Errorf("cannot reach Apps Script (network or fronting issue): %v\n  Hints: confirm the machine has internet access; try a different google_host (any 216.239.x.120 served by Google works)", err)
	}
	getBody, _ := io.ReadAll(io.LimitReader(getResp.Body, 4096))
	_ = getResp.Body.Close()

	if getResp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("deployment %s returned HTTP 404 — the Deployment ID in script_keys is wrong, the deployment was deleted, or the Web App was never published. Re-deploy with Deploy → New deployment, then update script_keys", shortScriptKey(scriptURL))
	}
	if bytes.Contains(bytes.ToLower(getBody), []byte("<html")) {
		return fmt.Errorf("deployment %s is not public (Apps Script returned HTML instead of the forwarder).\n  Fix: Deploy → Manage deployments → edit → set 'Who has access' to 'Anyone' and re-deploy", shortScriptKey(scriptURL))
	}
	trimmed := bytes.TrimSpace(getBody)
	var stats scriptStatsResponse
	if len(trimmed) > 0 && trimmed[0] == '{' && json.Unmarshal(trimmed, &stats) == nil && stats.OK {
		if stats.Version == 0 || stats.Protocol == 0 {
			return fmt.Errorf("apps script deployment %s is outdated (missing version info).\n  Fix: redeploy apps_script/Code.gs and update script_keys", shortScriptKey(scriptURL))
		}
		if stats.Protocol != protocol.ProtocolVersion {
			return fmt.Errorf("apps script protocol mismatch: script=%d client=%d.\n  Fix: redeploy apps_script/Code.gs", stats.Protocol, protocol.ProtocolVersion)
		}
	} else if bytes.Contains(getBody, []byte("GooseRelay")) {
		return fmt.Errorf("apps script deployment %s is outdated (legacy text response).\n  Fix: redeploy apps_script/Code.gs and update script_keys", shortScriptKey(scriptURL))
	} else {
		return fmt.Errorf("unexpected response from apps script %s (HTTP %d): %s", shortScriptKey(scriptURL), getResp.StatusCode, snippet(getBody))
	}

	// --- Probe 2: POST an encrypted probe frame to verify VPS reachability and AES key. ---
	return c.diagnosePost(ctx, scriptURL)
}

func (c *Client) diagnosePost(ctx context.Context, relayURL string) error {
	// We send a non-SYN frame for a random session ID. The server has no state
	// for that ID and immediately queues an RST in response, which we receive
	// in the same HTTP body. This avoids the server's 8s long-poll wait that
	// an empty batch would trigger, cutting pre-flight latency from ~10s to <1s.
	var probeID [frame.SessionIDLen]byte
	if _, rerr := rand.Read(probeID[:]); rerr != nil {
		return fmt.Errorf("internal: cannot generate probe session id: %w", rerr)
	}
	probePayload := protocol.EncodeProbePayload(c.clientVersion)
	probeFrame := &frame.Frame{
		SessionID: probeID,
		Flags:     frame.FlagACK,
		Payload:   probePayload,
	}
	body, err := c.encodeBatch([]*frame.Frame{probeFrame})
	if err != nil {
		return fmt.Errorf("internal: cannot encode probe batch: %w", err)
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, relayURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building POST request: %w", err)
	}
	postReq.Header.Set("Content-Type", c.requestContentType())
	postResp, err := c.pickHTTPClient().Do(postReq)
	if err != nil {
		return fmt.Errorf("probe POST failed: %w", err)
	}
	respBody, _ := io.ReadAll(io.LimitReader(postResp.Body, 64*1024))
	_ = postResp.Body.Close()

	switch postResp.StatusCode {
	case http.StatusOK:
		// Continue to body check below.
	case http.StatusNoContent:
		return fmt.Errorf("vps server rejected our probe (HTTP 204).\n  Most likely cause: AES key mismatch. The tunnel_key in client_config.json must be byte-identical to the one in server_config.json on the VPS")
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		if bytes.Contains(bytes.ToLower(respBody), []byte("<html")) {
			return fmt.Errorf("vps unreachable from apps script (HTTP %d, HTML error page).\n  Fix: confirm RELAY_URLS in Code.gs points to your VPS, that goose-server is running, and that the port is reachable from Google (try: curl http://YOUR.VPS.IP:8443/healthz from a different network)", postResp.StatusCode)
		}
		return fmt.Errorf("http %d from apps script — vps may be unreachable: %s", postResp.StatusCode, snippet(respBody))
	default:
		return fmt.Errorf("unexpected HTTP %d during probe: %s", postResp.StatusCode, snippet(respBody))
	}

	if !c.binaryDirect && isLikelyNonBatchRelayPayload(respBody) {
		reason, _ := classifyRelayErrorBody(respBody)
		if reason != "" {
			return fmt.Errorf("relay returned a non-batch response: %s", reason)
		}
		return fmt.Errorf("relay returned a non-batch response.\n  The apps script deployment may be misconfigured or hitting a quota error: %s", snippet(respBody))
	}
	_, rxFrames, err := c.decodeBatch(respBody)
	if err != nil {
		return fmt.Errorf("response from VPS could not be decrypted (%v).\n  Most likely cause: AES key mismatch. tunnel_key in client_config.json must be byte-identical to server_config.json on the VPS", err)
	}
	var serverInfo *protocol.VersionInfo
	for _, f := range rxFrames {
		if !f.HasFlag(frame.FlagRST) || len(f.Payload) == 0 {
			continue
		}
		info, perr := protocol.DecodeVersionInfo(f.Payload)
		if perr != nil || !info.OK {
			continue
		}
		serverInfo = info
		break
	}
	if serverInfo == nil {
		return fmt.Errorf("server did not return version info — likely an outdated goose-server deployment.\n  Fix: update goose-server on the VPS")
	}
	if serverInfo.Protocol != protocol.ProtocolVersion {
		return fmt.Errorf("server protocol mismatch: server=%d client=%d.\n  Fix: update goose-server or goose-client so they match", serverInfo.Protocol, protocol.ProtocolVersion)
	}
	return nil
}

// snippet returns the first ~120 bytes of body for use in error messages,
// trimmed and with control chars stripped.
func snippet(b []byte) string {
	const maxLen = 120
	t := bytes.TrimSpace(b)
	if len(t) > maxLen {
		t = t[:maxLen]
	}
	out := make([]byte, 0, len(t)+3)
	for _, c := range t {
		if c < 0x20 || c == 0x7f {
			out = append(out, ' ')
			continue
		}
		out = append(out, c)
	}
	if len(b) > maxLen {
		out = append(out, '.', '.', '.')
	}
	return string(out)
}
