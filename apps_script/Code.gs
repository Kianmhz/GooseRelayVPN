// GooseRelay forwarder.
//
// Apps Script web app deployed as: Execute as: Me, Access: Anyone.
// All traffic is AES-GCM encrypted by the client; this script is a dumb pipe
// and never sees plaintext or holds the key.
//
// Wire: client POSTs base64(encrypted batch). We forward the bytes verbatim
// to one of RELAY_URLS and return its response body verbatim.
//
// Replace RELAY_URLS with your VPS address(es) before deploying.

const RELAY_URLS = [
  // Replace YOUR.VPS.IP, and change 8443 only if server_config.json uses a different server_port.
  'http://YOUR.VPS.IP:8443/tunnel',
];
const FORWARDER_VERSION = 2;
const PROTOCOL_VERSION = 1;
const ENABLE_INVOCATION_COUNTING = false;
// Valid client uploads are capped by max_request_body_bytes on the VPS
// (12 MiB in the example configs). Reject larger public probes before
// spending UrlFetch quota. Raise this only if you also raise the Go client and
// server upload caps.
const MAX_TUNNEL_PAYLOAD_CHARS = 12 * 1024 * 1024;
const FORWARD_TIMEOUT_SECONDS = 30;
// RELAY_URLS must point to the VPS /tunnel endpoint. If this script is pointed
// back at an Apps Script web-app URL, each request can loop through Google and
// burn quota without ever reaching the VPS. Cover the normal deployment URL,
// Workspace-domain URLs, and googleusercontent redirect targets.
const GAS_RELAY_LOOP_RE = /^https?:\/\/(?:script\.google\.com|script\.googleusercontent\.com)(?::\d+)?\/(?:macros|a\/macros\/[^/?#]+)(?:\/|$)/i;
const BASE64_SAMPLE_RE = /^[A-Za-z0-9+/=]+$/;

function doPost(e) {
  for (let i = 0; i < RELAY_URLS.length; i++) {
    if (isAppsScriptRelayURL_(RELAY_URLS[i])) {
      // Throw so Apps Script returns an HTTP error. Returning HTTP 200 with
      // this diagnostic text would make clients parse it as a tunnel batch.
      throw new Error('relay_loop_detected: RELAY_URLS must point to your VPS /tunnel endpoint, not Apps Script');
    }
  }
  const payload = (e && e.postData && e.postData.contents) || '';
  if (!looksLikeTunnelPayload_(payload)) {
    return ContentService
      .createTextOutput(JSON.stringify({ e: 'bad_payload', body: 'POST body is not a GooseRelay encrypted batch' }))
      .setMimeType(ContentService.MimeType.JSON);
  }
  if (ENABLE_INVOCATION_COUNTING) {
    bumpInvocationCount_();
  }
  let lastError = 'no RELAY_URLS configured';
  for (let i = 0; i < RELAY_URLS.length; i++) {
    try {
      const resp = UrlFetchApp.fetch(RELAY_URLS[i], {
        method: 'post',
        contentType: 'text/plain',
        payload: payload,
        muteHttpExceptions: true,
        followRedirects: false,
        timeoutSeconds: FORWARD_TIMEOUT_SECONDS,  // keep failover faster than Apps Script's 6-minute cap
      });
      const status = resp.getResponseCode();
      const text = resp.getContentText();
      if (status === 200) {
        return ContentService
          .createTextOutput(text)
          .setMimeType(ContentService.MimeType.TEXT);
      }
      lastError = 'upstream status ' + status + ': ' + text.slice(0, 1024);
    } catch (err) {
      lastError = 'upstream fetch error: ' + String(err);
    }
  }
  // All RELAY_URLS failed. Throw so Apps Script returns HTTP 500 and the
  // GooseRelay client treats this as a clean endpoint failure instead of
  // trying to base64-decode an error string.
  throw new Error(lastError);
}

function isAppsScriptRelayURL_(url) {
  return GAS_RELAY_LOOP_RE.test(String(url || '').trim());
}

function looksLikeTunnelPayload_(payload) {
  const text = String(payload || '');
  // A valid empty encrypted GooseRelay text batch is roughly 63 base64 chars.
  // Check only a small head/tail sample so multi-megabyte uploads don't spend
  // Apps Script CPU scanning the whole body. The VPS crypto/frame decoder is
  // still the authoritative full-body validator; this only filters obvious
  // public web probes before spending UrlFetch quota.
  if (text.length < 40) return false;
  if (text.length > MAX_TUNNEL_PAYLOAD_CHARS) return false;
  if (text.length % 4 === 1) return false;
  const head = text.slice(0, 128);
  const tail = text.length > 128 ? text.slice(-32) : '';
  return BASE64_SAMPLE_RE.test(head) &&
    (tail === '' || BASE64_SAMPLE_RE.test(tail));
}

// doGet returns this deployment's optional per-day web-app request count so the
// client can show a rough local pressure signal alongside its own counter. This
// is not an exact Google URL Fetch quota counter: one valid tunnel request may
// try more than one RELAY_URLS entry, and rejected public probes may spend zero
// UrlFetch calls. This Pacific date is only a human-readable local window;
// Google documents Apps Script quotas as per-user windows that reset 24 hours
// after first use.
// Format is JSON so the client can parse without ambiguity:
//   {"ok":true,"date":"2026-05-04","count":1234,"counting_enabled":true}
function doGet(e) {
  if (e && e.parameter && e.parameter.legacy === '1') {
    return ContentService
      .createTextOutput('GooseRelay forwarder OK')
      .setMimeType(ContentService.MimeType.TEXT);
  }
  const today = pacificDateKey_();
  let count = null;
  if (ENABLE_INVOCATION_COUNTING) {
    const props = PropertiesService.getScriptProperties();
    count = parseInt(props.getProperty('count_' + today) || '0', 10);
  }
  const out = {
    ok: true,
    date: today,
    count: count,
    counting_enabled: ENABLE_INVOCATION_COUNTING,
    max_payload_chars: MAX_TUNNEL_PAYLOAD_CHARS,
    timeout_seconds: FORWARD_TIMEOUT_SECONDS,
    relay_count: RELAY_URLS.length,
    version: FORWARDER_VERSION,
    protocol: PROTOCOL_VERSION,
  };
  return ContentService
    .createTextOutput(JSON.stringify(out))
    .setMimeType(ContentService.MimeType.JSON);
}

function pacificDateKey_() {
  return Utilities.formatDate(new Date(), 'America/Los_Angeles', 'yyyy-MM-dd');
}

// bumpInvocationCount_ records one invocation in PropertiesService keyed by
// today's PT date. Best-effort: under high concurrency two requests may read
// the same value and write the same incremented number, slightly under-counting.
// That's acceptable for an informational counter; adding a LockService gate
// would add tens of ms to every tunnel request, which costs more than perfect
// accuracy is worth.
function bumpInvocationCount_() {
  try {
    const props = PropertiesService.getScriptProperties();
    const today = pacificDateKey_();
    const key = 'count_' + today;
    const raw = props.getProperty(key);
    if (raw === null) {
      // First request of a new day; purge yesterday's keys so the property
      // store doesn't grow unbounded (Google documents 9 KB per value and
      // 500 KB total storage per property store).
      pruneStaleCounts_(props, today);
    }
    const cur = raw === null ? 0 : parseInt(raw, 10);
    props.setProperty(key, String(cur + 1));
  } catch (err) {
    // Property writes can fail under contention; counting is informational
    // so we swallow the error rather than break the tunnel request.
  }
}

function pruneStaleCounts_(props, today) {
  const keys = props.getKeys();
  const keep = 'count_' + today;
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    if (k.indexOf('count_') === 0 && k !== keep) {
      props.deleteProperty(k);
    }
  }
}
