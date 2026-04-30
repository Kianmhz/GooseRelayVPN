// GooseRelay forwarder.
//
// Apps Script web app deployed as: Execute as: Me, Access: Anyone (or Anyone with Google account).
// All traffic is AES-GCM encrypted by the client; this script is a dumb pipe
// and never sees plaintext or holds the key.
//
// Wire: client POSTs base64(encrypted batch). We forward the bytes verbatim
// to DO_URL and return its response body verbatim.
//
// Replace DO_URL with your VPS address before deploying.

const DO_URL = 'http://YOUR.DO.IP:8443/tunnel';

function doPost(e) {
  const payload = (e && e.postData && e.postData.contents) || '';
  const resp = UrlFetchApp.fetch(DO_URL, {
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

function doGet() {
  return ContentService
    .createTextOutput('GooseRelay forwarder OK')
    .setMimeType(ContentService.MimeType.TEXT);
}
