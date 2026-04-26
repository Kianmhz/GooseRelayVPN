#!/usr/bin/env bash
# Deploy the relay-tunnel exit server to a remote host.
#
# Usage: bash scripts/deploy.sh root@146.190.246.7
#        bash scripts/deploy.sh root@YOUR_IP [server_config.json]
#
# Requirements: go, ssh, scp in PATH; server already accessible.
set -euo pipefail

REMOTE="${1:-}"
CONFIG="${2:-server_config.json}"

if [[ -z "$REMOTE" ]]; then
  echo "Usage: $0 user@host [server_config.json]" >&2
  exit 1
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "Error: config file '$CONFIG' not found." >&2
  echo "Copy server_config.example.json → server_config.json and fill in aes_key_hex." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$ROOT/relay-server-linux"
SERVICE="$ROOT/scripts/relay-tunnel.service"

echo "==> Building Linux amd64 binary..."
cd "$ROOT"
GOOS=linux GOARCH=amd64 go build -o "$BINARY" ./cmd/server
echo "    Built: $BINARY ($(du -sh "$BINARY" | cut -f1))"

echo "==> Copying binary and config to $REMOTE..."
scp "$BINARY" "$CONFIG" "$SERVICE" "$REMOTE:/root/"

echo "==> Installing and starting systemd service on $REMOTE..."
ssh "$REMOTE" bash <<'EOF'
  set -euo pipefail
  mv /root/relay-tunnel.service /etc/systemd/system/relay-tunnel.service
  chmod +x /root/relay-server-linux
  systemctl daemon-reload
  systemctl enable relay-tunnel
  systemctl restart relay-tunnel
  sleep 1
  systemctl status relay-tunnel --no-pager
EOF

echo ""
echo "==> Done. Testing /healthz..."
IP=$(echo "$REMOTE" | sed 's/.*@//')
curl -sf --max-time 5 "http://$IP:8443/healthz" && echo "  OK — server is live."
