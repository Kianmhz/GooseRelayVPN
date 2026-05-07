// GooseRelay forwarder.
//
// Apps Script web app deployed as: Execute as: Me, Access: Anyone (or Anyone with Google account).
// All traffic is AES-GCM encrypted by the client; this script is a dumb pipe
// and never sees plaintext or holds the key.
//
// Wire: client POSTs base64(encrypted batch). We forward the bytes verbatim
// to RELAY_URL and return its response body verbatim.
//
// Replace RELAY_URL with your VPS address before deploying.

const RELAY_URL = 'http://YOUR.VPS.IP:8443/tunnel';
const FORWARDER_VERSION = 1;
const PROTOCOL_VERSION = 1;

function doPost(e) {
  bumpInvocationCount_();
  const payload = (e && e.postData && e.postData.contents) || '';
  const resp = UrlFetchApp.fetch(RELAY_URL, {
    method: 'post',
    contentType: 'text/plain',
    payload: payload,
    muteHttpExceptions: true,
    followRedirects: false,
    deadline: 30,  // seconds; long-poll window is kept at 8s for Apps Script stability
  });
  return ContentService
    .createTextOutput(resp.getContentText())
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
