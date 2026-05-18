// GooseRelay forwarder.
//
// Apps Script web app deployed as: Execute as: Me, Access: Anyone (or Anyone with Google account).
// All traffic is AES-GCM encrypted by the client; this script is a dumb pipe
// and never sees plaintext or holds the key.
//
// Wire: client POSTs base64(encrypted batch). We forward the bytes verbatim
// to one of RELAY_URLS and return its response body verbatim.
//
// Replace RELAY_URLS with your VPS address(es) before deploying.

const RELAY_URLS = [
  // Replace YOUR_SERVER_PORT with server_config.json's server_port.
  // The dist/server_config.json used for the current test listens on 5443.
  'http://YOUR.VPS.IP:YOUR_SERVER_PORT/tunnel',
];
const FORWARDER_VERSION = 1;
const PROTOCOL_VERSION = 1;
const ENABLE_INVOCATION_COUNTING = false;
const GAS_RELAY_LOOP_RE = /^https?:\/\/script\.google\.com\/macros\//i;

function doPost(e) {
  for (let i = 0; i < RELAY_URLS.length; i++) {
    if (GAS_RELAY_LOOP_RE.test(RELAY_URLS[i])) {
      return ContentService
        .createTextOutput('relay_loop_detected: RELAY_URLS must point to your VPS /tunnel endpoint, not Apps Script')
        .setMimeType(ContentService.MimeType.TEXT);
    }
  }
  if (ENABLE_INVOCATION_COUNTING) {
    bumpInvocationCount_();
  }
  const payload = (e && e.postData && e.postData.contents) || '';
  let lastText = '';
  for (let i = 0; i < RELAY_URLS.length; i++) {
    try {
      const resp = UrlFetchApp.fetch(RELAY_URLS[i], {
        method: 'post',
        contentType: 'text/plain',
        payload: payload,
        muteHttpExceptions: true,
        followRedirects: false,
        deadline: 30,  // seconds; long-poll window is kept below this for Apps Script stability
      });
      const status = resp.getResponseCode();
      const text = resp.getContentText();
      lastText = text;
      if (status === 200) {
        return ContentService
          .createTextOutput(text)
          .setMimeType(ContentService.MimeType.TEXT);
      }
      lastText = JSON.stringify({
        e: 'upstream_status',
        status: status,
        body: text.slice(0, 1024),
      });
    } catch (err) {
      lastText = String(err);
    }
  }
  return ContentService
    .createTextOutput(lastText)
    .setMimeType(ContentService.MimeType.TEXT);
}

// doGet returns this deployment's per-day invocation count so the client can
// log real per-deployment usage alongside its own client-side counter. The
// day boundary tracks the Apps Script quota window (midnight Pacific). Format
// is JSON so the client can parse without ambiguity:
//   {"ok":true,"date":"2026-05-04","count":1234}
function doGet(e) {
  if (e && e.parameter && e.parameter.legacy === '1') {
    return ContentService
      .createTextOutput('GooseRelay forwarder OK')
      .setMimeType(ContentService.MimeType.TEXT);
  }
  const props = PropertiesService.getScriptProperties();
  const today = pacificDateKey_();
  const count = parseInt(props.getProperty('count_' + today) || '0', 10);
  const out = {
    ok: true,
    date: today,
    count: count,
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
// That's acceptable for an informational counter — adding a LockService gate
// would add tens of ms to every tunnel request, which costs more than perfect
// accuracy is worth.
function bumpInvocationCount_() {
  try {
    const props = PropertiesService.getScriptProperties();
    const today = pacificDateKey_();
    const key = 'count_' + today;
    const raw = props.getProperty(key);
    if (raw === null) {
      // First request of a new day — purge yesterday's keys so the property
      // store doesn't grow unbounded (capped at 9 KB / 500 entries by Google).
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
