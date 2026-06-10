#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROJECT_DIR="$(cd -- "$PROJECT_DIR" && pwd)"

APP_NAME="${NOVASENTINEL_CLOUD_APP_NAME:-novasentinel-premium-cloud}"
APP_USER="${NOVASENTINEL_CLOUD_APP_USER:-novasentinel}"
APP_GROUP="${NOVASENTINEL_CLOUD_APP_GROUP:-$APP_USER}"
APP_DIR="${NOVASENTINEL_CLOUD_APP_DIR:-/opt/$APP_NAME}"
NODE_BIN="${NOVASENTINEL_NODE_BIN:-}"
HOST="${NOVASENTINEL_CLOUD_HOST:-0.0.0.0}"
PORT="${NOVASENTINEL_CLOUD_PORT:-8780}"
DATA_DIR="${NOVASENTINEL_PREMIUM_DB_DIR:-/var/lib/$APP_NAME}"
DB_PATH="${NOVASENTINEL_PREMIUM_DB:-$DATA_DIR/premium_cloud.sqlite3}"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root (sudo)."
  exit 1
fi

if ! command -v node >/dev/null 2>&1 && [[ -z "$NODE_BIN" ]]; then
  echo "Node.js is required on this server for deployment."
  echo "Install it first (apt install nodejs) or set NOVASENTINEL_NODE_BIN."
  exit 1
fi

if [[ -z "$NODE_BIN" ]]; then
  NODE_BIN="$(command -v node)"
fi

if [[ ! -x "$NODE_BIN" ]]; then
  echo "Configured Node binary is not executable: $NODE_BIN"
  exit 1
fi

if [[ ! -f "$PROJECT_DIR/server.js" ]]; then
  echo "Could not find premium_cloud server entrypoint in $PROJECT_DIR."
  exit 1
fi

if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin "$APP_USER"
fi

mkdir -p "$APP_DIR"
mkdir -p "$DATA_DIR"

if command -v rsync >/dev/null 2>&1; then
  rsync -a \
    --delete \
    --exclude ".git" \
    --exclude "node_modules" \
    --exclude "data" \
    --exclude "*.log" \
    "$PROJECT_DIR/" "$APP_DIR/"
else
  cp -r "$PROJECT_DIR/"* "$APP_DIR/"
  rm -rf "$APP_DIR/data" 2>/dev/null || true
fi

cp -a "$PROJECT_DIR/data/"* "$DATA_DIR/" 2>/dev/null || true
ln -sfn "$DATA_DIR" "$APP_DIR/data"
if [[ ! -f "$APP_DIR/data/premium_cloud.sqlite3" && ! -L "$APP_DIR/data/premium_cloud.sqlite3" ]]; then
  : > "$APP_DIR/data/premium_cloud.sqlite3"
fi

chown -R "$APP_USER:$APP_GROUP" "$APP_DIR" "$DATA_DIR"
chmod -R 0750 "$APP_DIR/data"
chmod +x "$APP_DIR/tools/run-premium-cloud.sh"

cat > "$APP_DIR/.env" <<EOF
HOST=$HOST
PORT=$PORT
NODE_ENV=production
NOVASENTINEL_PREMIUM_DB=$DB_PATH
EOF

cat > /etc/systemd/system/$APP_NAME.service <<EOF
[Unit]
Description=NovaSentinel Premium Cloud
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$NODE_BIN $APP_DIR/tools/run-premium-cloud.sh
EnvironmentFile=$APP_DIR/.env
Restart=on-failure
RestartSec=5
User=$APP_USER
Group=$APP_GROUP
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF

(cd "$APP_DIR" && npm ci --omit=dev --no-audit --no-fund)
systemctl daemon-reload
systemctl enable "$APP_NAME"
systemctl restart "$APP_NAME"
sleep 1
systemctl --no-pager status "$APP_NAME" --full --lines=12

cat <<EOF2
Deployment completed.
- Application directory: $APP_DIR
- Public URL: http://$HOST:$PORT
- Service name: $APP_NAME
- Database data directory: $DATA_DIR

You can manage with:
  systemctl status $APP_NAME
  systemctl restart $APP_NAME
  systemctl stop $APP_NAME
EOF2
