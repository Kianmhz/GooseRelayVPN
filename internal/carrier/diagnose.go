package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/protocol"
)

type diagnoseEndpointError struct {
	err  error
	kind relayErrorKind
}

func (e *diagnoseEndpointError) Error() string { return e.err.Error() }
func (e *diagnoseEndpointError) Unwrap() error { return e.err }

func diagnoseError(kind relayErrorKind, format string, args ...any) error {
	return &diagnoseEndpointError{
		err:  fmt.Errorf(format, args...),
		kind: kind,
	}
}

// Diagnose performs one-shot end-to-end health checks against configured relay
// endpoints and returns nil if at least one endpoint is wired up correctly.
// Failed endpoints are folded into the normal endpoint-health state so a
// quota-dead or misconfigured deployment is kept out of rotation before the
// user's browser starts sending real traffic.
//
// The two Apps Script probes:
//
//  1. GET <scriptURL>/exec confirms the deployment is live and public, and
//     reads the forwarder/protocol version from doGet metadata.
//  2. POST an encrypted probe batch verifies Apps Script can reach the VPS and
//     that the client/server tunnel_key can decrypt the same batch.
func (c *Client) Diagnose(ctx context.Context) error {
	c.endpointMu.Lock()
	if len(c.endpoints) == 0 {
		c.endpointMu.Unlock()
		return fmt.Errorf("no relay endpoints configured")
	}
	leases := make([]endpointLease, len(c.endpoints))
	for i := range c.endpoints {
		leases[i] = endpointLease{
			idx:        i,
			url:        c.endpoints[i].url,
			bucket:     c.endpoints[i].bucket,
			generation: c.endpointGen,
			check:      true,
		}
	}
	c.endpointMu.Unlock()

	healthy := 0
	skipped := 0
	failures := make([]string, 0, len(leases))
	for _, lease := range leases {
		if ctx.Err() != nil {
			break
		}
		if c.endpointUnavailableForDiagnose(lease) {
			skipped++
			continue
		}
		scriptURL := lease.url
		if err := c.diagnoseEndpoint(ctx, scriptURL); err != nil {
			c.markEndpointDiagnoseFailure(lease, err)
			failures = append(failures, fmt.Sprintf("%s: %v", shortScriptKey(scriptURL), err))
			continue
		}
		healthy++
	}
	if healthy > 0 {
		if len(failures)+skipped > 0 {
			log.Printf("[carrier] pre-flight kept %d/%d relay endpoint(s); quarantined %d failing endpoint(s)",
				healthy, len(leases), len(failures)+skipped)
		}
		return nil
	}
	if len(failures) == 0 && ctx.Err() != nil {
		return ctx.Err()
	}
	if len(failures) == 0 && skipped > 0 {
		return fmt.Errorf("pre-flight skipped all %d relay endpoint(s) because they are currently quarantined", len(leases))
	}
	return fmt.Errorf("pre-flight failed for all %d relay endpoint(s):\n%s",
		len(leases), strings.Join(failures, "\n"))
}

func (c *Client) endpointUnavailableForDiagnose(lease endpointLease) bool {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if !c.endpointLeaseMatchesLocked(lease) {
		return true
	}
	return c.endpointUnavailableLocked(&c.endpoints[lease.idx], time.Now())
}

func (c *Client) diagnoseEndpoint(ctx context.Context, scriptURL string) error {
	if !c.useFronting {
		return c.diagnosePost(ctx, scriptURL)
	}

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
	if err != nil {
		return diagnoseError(relayErrorHard, "building GET request: %w", err)
	}
	getResp, err := c.pickHTTPClient().Do(getReq)
	if err != nil {
		return fmt.Errorf("cannot reach Apps Script (network or fronting issue): %w\n  Hints: confirm the machine has internet access; try a different current Google edge IP in google_host and let the startup probe keep only working hosts", safeWrappedError(err))
	}
	getBody, _ := io.ReadAll(io.LimitReader(getResp.Body, 4096))
	_ = getResp.Body.Close()

	if getResp.StatusCode == http.StatusTooManyRequests {
		return diagnoseError(relayErrorRateLimit, "deployment %s returned HTTP 429 - Apps Script is rate-limiting this deployment; backing off and trying another endpoint", shortScriptKey(scriptURL))
	}
	if getResp.StatusCode == http.StatusNotFound {
		return diagnoseError(relayErrorHard, "deployment %s returned HTTP 404 - the Deployment ID in script_keys is wrong, the deployment was deleted, or the Web App was never published. Re-deploy with Deploy -> New deployment, then update script_keys", shortScriptKey(scriptURL))
	}
	if bytes.Contains(bytes.ToLower(getBody), []byte("<html")) {
		return diagnoseError(relayErrorHard, "deployment %s is not public (Apps Script returned HTML instead of the forwarder).\n  Fix: Deploy -> Manage deployments -> edit -> set 'Who has access' to 'Anyone' and re-deploy", shortScriptKey(scriptURL))
	}
	trimmed := bytes.TrimSpace(getBody)
	var stats scriptStatsResponse
	if len(trimmed) > 0 && trimmed[0] == '{' && json.Unmarshal(trimmed, &stats) == nil && stats.OK {
		if stats.Version == 0 || stats.Protocol == 0 {
			return diagnoseError(relayErrorHard, "apps script deployment %s is outdated (missing version info).\n  Fix: redeploy apps_script/Code.gs and update script_keys", shortScriptKey(scriptURL))
		}
		if stats.Protocol != protocol.ProtocolVersion {
			return diagnoseError(relayErrorHard, "apps script protocol mismatch: script=%d client=%d.\n  Fix: redeploy apps_script/Code.gs", stats.Protocol, protocol.ProtocolVersion)
		}
	} else if bytes.Contains(getBody, []byte("GooseRelay")) {
		return diagnoseError(relayErrorHard, "apps script deployment %s is outdated (legacy text response).\n  Fix: redeploy apps_script/Code.gs and update script_keys", shortScriptKey(scriptURL))
	} else {
		return diagnoseError(relayErrorSoft, "unexpected response from apps script %s (HTTP %d): %s", shortScriptKey(scriptURL), getResp.StatusCode, snippet(getBody))
	}

	return c.diagnosePost(ctx, scriptURL)
}

func (c *Client) markEndpointDiagnoseFailure(lease endpointLease, err error) {
	var diagErr *diagnoseEndpointError
	kind := relayErrorSoft
	if errors.As(err, &diagErr) {
		kind = diagErr.kind
	}
	switch kind {
	case relayErrorDailyQuota:
		c.recordEndpointFailureReasonLease(lease, endpointFailureQuota)
		c.markEndpointQuotaExhaustedLease(lease)
	case relayErrorRateLimit:
		c.recordEndpointFailureReasonLease(lease, endpointFailureRateLimit)
		c.markEndpoint429Lease(lease)
	case relayErrorHard:
		c.recordEndpointFailureReasonLease(lease, endpointFailureNonBatch)
		c.markEndpointHardFailureLease(lease)
	default:
		if isLocalNetworkOffline(err) {
			c.recordEndpointFailureReasonLease(lease, endpointFailureLocalOffline)
			c.markEndpointLocalNetworkFailureLease(lease)
			return
		}
		c.recordEndpointFailureReasonLease(lease, endpointFailureHTTPError)
		c.markEndpointFailureLease(lease)
	}
}

func (c *Client) newVersionProbeFrame() (*frame.Frame, error) {
	var probeID [frame.SessionIDLen]byte
	if _, rerr := rand.Read(probeID[:]); rerr != nil {
		return nil, fmt.Errorf("generate probe session id: %w", rerr)
	}
	probePayload := protocol.EncodeProbePayloadWithOptions(c.clientVersion, protocol.ProbeOptions{
		ClientInstanceID: c.clientInstanceID,
		RunID:            c.clientRunID,
		ResetPrevious:    c.freshStartReset && c.clientInstanceID != "",
	})
	return &frame.Frame{
		SessionID: probeID,
		Flags:     frame.FlagACK,
		Payload:   probePayload,
	}, nil
}

func (c *Client) diagnosePost(ctx context.Context, relayURL string) error {
	// We send a non-SYN frame for a random session ID. The server has no state
	// for that ID and immediately queues an RST in response, which we receive
	// in the same HTTP body. This avoids the server's long-poll wait that an
	// empty batch would trigger.
	probeFrame, err := c.newVersionProbeFrame()
	if err != nil {
		return diagnoseError(relayErrorHard, "internal: cannot build probe frame: %w", err)
	}
	body, err := c.encodeBatch([]*frame.Frame{probeFrame})
	if err != nil {
		return diagnoseError(relayErrorHard, "internal: cannot encode probe batch: %w", err)
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, relayURL, bytes.NewReader(body))
	if err != nil {
		return diagnoseError(relayErrorHard, "building POST request: %w", err)
	}
	postReq.Header.Set("Content-Type", c.requestContentType())
	postResp, err := c.pickHTTPClient().Do(postReq)
	if err != nil {
		return fmt.Errorf("probe POST failed: %w", safeWrappedError(err))
	}
	respBody, _ := io.ReadAll(io.LimitReader(postResp.Body, 64*1024))
	_ = postResp.Body.Close()

	if !c.useFronting {
		switch postResp.StatusCode {
		case http.StatusOK:
		case http.StatusNoContent:
			return diagnoseError(relayErrorHard, "vps server rejected our probe (HTTP 204).\n  Most likely cause: AES key mismatch. The tunnel_key in client_config.json must be byte-identical to the one in server_config.json on the VPS")
		case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			if bytes.Contains(bytes.ToLower(respBody), []byte("<html")) {
				return diagnoseError(relayErrorSoft, "direct relay returned HTTP %d with an HTML error page.\n  Fix: confirm relay_urls points to your goose-server /tunnel URL, that goose-server is running, and that the VPS firewall allows the port", postResp.StatusCode)
			}
			return diagnoseError(relayErrorSoft, "HTTP %d from direct relay: %s", postResp.StatusCode, snippet(respBody))
		case http.StatusTooManyRequests:
			return diagnoseError(relayErrorRateLimit, "direct relay returned HTTP 429 - backing off and trying another endpoint")
		default:
			return diagnoseError(relayErrorHard, "unexpected HTTP %d during probe: %s", postResp.StatusCode, snippet(respBody))
		}
	}

	switch postResp.StatusCode {
	case http.StatusOK:
	case http.StatusNoContent:
		return diagnoseError(relayErrorHard, "vps server rejected our probe (HTTP 204).\n  Most likely cause: AES key mismatch. The tunnel_key in client_config.json must be byte-identical to the one in server_config.json on the VPS")
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		if bytes.Contains(bytes.ToLower(respBody), []byte("<html")) {
			return diagnoseError(relayErrorSoft, "vps unreachable from apps script (HTTP %d, HTML error page).\n  Fix: confirm RELAY_URLS in Code.gs points to your VPS, that goose-server is running, and that the port is reachable from Google (try: curl http://YOUR.VPS.IP:8443/healthz from a different network)", postResp.StatusCode)
		}
		return diagnoseError(relayErrorSoft, "http %d from apps script - vps may be unreachable: %s", postResp.StatusCode, snippet(respBody))
	case http.StatusTooManyRequests:
		return diagnoseError(relayErrorRateLimit, "Apps Script returned HTTP 429 - this deployment is temporarily rate-limited; backing off and trying another endpoint")
	default:
		return diagnoseError(relayErrorHard, "unexpected HTTP %d during probe: %s", postResp.StatusCode, snippet(respBody))
	}

	if !c.binaryDirect && isLikelyNonBatchRelayPayload(respBody) {
		reason, kind := classifyRelayErrorBodyKind(respBody)
		if reason != "" {
			return diagnoseError(kind, "relay returned a non-batch response: %s", reason)
		}
		if !c.useFronting {
			return diagnoseError(relayErrorSoft, "relay returned a non-batch response.\n  The direct relay URL may not point to goose-server /tunnel: %s", snippet(respBody))
		}
		return diagnoseError(relayErrorSoft, "relay returned a non-batch response.\n  The apps script deployment may be misconfigured or hitting a quota error: %s", snippet(respBody))
	}
	_, rxFrames, err := c.decodeBatch(respBody)
	if err != nil {
		return diagnoseError(relayErrorHard, "response from VPS could not be decrypted (%v).\n  Most likely cause: AES key mismatch. tunnel_key in client_config.json must be byte-identical to server_config.json on the VPS", err)
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
		return diagnoseError(relayErrorHard, "server did not return version info - likely an outdated goose-server deployment.\n  Fix: update goose-server on the VPS")
	}
	if serverInfo.Protocol != protocol.ProtocolVersion {
		return diagnoseError(relayErrorHard, "server protocol mismatch: server=%d client=%d.\n  Fix: update goose-server or goose-client so they match", serverInfo.Protocol, protocol.ProtocolVersion)
	}
	c.applyVersionFeatures(serverInfo)
	return nil
}

func (c *Client) applyVersionFeatures(info *protocol.VersionInfo) {
	if info == nil {
		c.downstreamReplayActive.Store(false)
		return
	}
	if !c.useFronting {
		c.binaryDirect = protocol.HasFeature(info.Features, protocol.FeatureBinaryBatchV1)
	}
	if c.downstreamReplayMode != downstreamReplayModeAuto {
		c.downstreamReplayActive.Store(false)
		return
	}
	c.downstreamReplayActive.Store(protocol.HasFeature(info.Features, protocol.FeatureDownstreamReplayV1))
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
