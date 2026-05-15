# Changelog

## Unreleased

### Added

- Direct VPS stream transport over `/stream`, with existing Apps Script and
  direct POST modes preserved as fallback paths.
- Binary direct batch mode for direct VPS transports.
- Server-side `max_sessions` limit.
- Graceful server shutdown on SIGINT/SIGTERM.
- Stream reconnect grace period before server-side sessions are aborted.
- Fuzz entry points for frame and batch decoding.
- Architecture documentation in `docs/ARCHITECTURE.md`.

### Changed

- Client shutdown now logs whether session cleanup completed before timeout.
- Server request bodies are rejected early when `Content-Length` exceeds the
  configured maximum.
- Hot idle timers use reusable timers in the client worker and server long-poll
  wait paths.
- Closed tunnel sessions now surface `io.ErrClosedPipe` through the SOCKS
  adapter instead of silently accepting writes.

### Fixed

- Server request size is independent from the response pre-encode budget.
- Direct stream routing uses the same parallel SYN handling as POST routing.
- DNS cache dials multiple resolved addresses and promotes the last successful
  address.
- Server session routing re-checks ownership before delivering frames.
