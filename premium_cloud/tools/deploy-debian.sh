#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROJECT_DIR="$(cd -- "$PROJECT_DIR" && pwd)"
REPO_DIR="$(cd -- "$PROJECT_DIR/.." && pwd)"

APP_NAME="${NOVASENTINEL_CLOUD_APP_NAME:-novasentinel-premium-cloud}"
APP_USER="${NOVASENTINEL_CLOUD_APP_USER:-novasentinel}"
APP_GROUP="${NOVASENTINEL_CLOUD_APP_GROUP:-$APP_USER}"
APP_DIR="${NOVASENTINEL_CLOUD_APP_DIR:-/opt/$APP_NAME}"
NODE_BIN="${NOVASENTINEL_NODE_BIN:-}"
HOST="${NOVASENTINEL_CLOUD_HOST:-0.0.0.0}"
PORT="${NOVASENTINEL_CLOUD_PORT:-8780}"
DATA_DIR="${NOVASENTINEL_PREMIUM_DB_DIR:-/var/lib/$APP_NAME}"
DB_PATH="${NOVASENTINEL_PREMIUM_DB:-$DATA_DIR/premium_cloud.sqlite3}"
DOWNLOAD_DIR="${NOVASENTINEL_DOWNLOAD_DIR:-$DATA_DIR/downloads}"
GITHUB_REPO="${NOVASENTINEL_GITHUB_REPO:-MonkeyTime/NovaSentinel}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

log() {
  printf '[NovaSentinel deploy] %s\n' "$*"
}

upsert_env() {
  local file="$1"
  local key="$2"
  local value="$3"
  local escaped
  escaped="$(printf '%s' "$value" | sed -e 's/[&|]/\\&/g')"
  touch "$file"
  if grep -qE "^${key}=" "$file"; then
    sed -i "s|^${key}=.*|${key}=${escaped}|" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

set_env_if_missing() {
  local file="$1"
  local key="$2"
  local value="${3:-}"
  touch "$file"
  if ! grep -qE "^${key}=" "$file"; then
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

backup_env_file() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  local backup_dir="$DATA_DIR/env-backups"
  local backup_file
  backup_file="$backup_dir/.env.$(date +%Y%m%d%H%M%S).bak"
  mkdir -p "$backup_dir"
  cp -a "$file" "$backup_file"
  chmod 0640 "$backup_file" || true
  log "Existing .env backed up to $backup_file"
}

archive_legacy_env_backups() {
  local backup_dir="$DATA_DIR/env-backups"
  local found=0
  shopt -s nullglob
  for file in "$APP_DIR"/.env.*.bak "$APP_DIR"/.env.bak; do
    [[ -f "$file" ]] || continue
    mkdir -p "$backup_dir"
    mv "$file" "$backup_dir/$(basename "$file")"
    found=1
  done
  shopt -u nullglob
  if [[ "$found" == "1" ]]; then
    chown -R root:"$APP_GROUP" "$backup_dir"
    chmod 0750 "$backup_dir"
    chmod 0640 "$backup_dir"/.env*.bak 2>/dev/null || true
    log "Legacy .env backups moved to $backup_dir"
  fi
}

latest_matching_file() {
  local pattern="$1"
  shift
  local dir
  for dir in "$@"; do
    [[ -d "$dir" ]] || continue
    find "$dir" -maxdepth 1 -type f -iname "$pattern" -printf '%T@ %p\n' 2>/dev/null || true
  done | sort -nr | head -n 1 | cut -d' ' -f2-
}

copy_download_asset() {
  local source="$1"
  local canonical_name="$2"
  [[ -n "$source" && -f "$source" ]] || return 0
  install -m 0640 -o "$APP_USER" -g "$APP_GROUP" "$source" "$DOWNLOAD_DIR/$(basename "$source")"
  install -m 0640 -o "$APP_USER" -g "$APP_GROUP" "$source" "$DOWNLOAD_DIR/$canonical_name"
  log "Download asset ready: $DOWNLOAD_DIR/$canonical_name <- $(basename "$source")"
}

download_github_release_asset() {
  local regex="$1"
  local canonical_name="$2"
  log "Looking for GitHub Release asset matching $regex in $GITHUB_REPO."
  GITHUB_REPO="$GITHUB_REPO" \
  GITHUB_TOKEN="$GITHUB_TOKEN" \
  ASSET_REGEX="$regex" \
  DOWNLOAD_DIR="$DOWNLOAD_DIR" \
  CANONICAL_NAME="$canonical_name" \
  node <<'NODE'
const fs = require("node:fs");
const path = require("node:path");

const repo = process.env.GITHUB_REPO;
const token = process.env.GITHUB_TOKEN || "";
const assetRegex = new RegExp(process.env.ASSET_REGEX, "i");
const downloadDir = process.env.DOWNLOAD_DIR;
const canonicalName = process.env.CANONICAL_NAME;

async function request(url, accept = "application/vnd.github+json") {
  const response = await fetch(url, {
    headers: {
      "Accept": accept,
      "User-Agent": "NovaSentinel-Ubuntu-Deploy",
      ...(token ? { "Authorization": `Bearer ${token}` } : {}),
    },
  });
  if (!response.ok) {
    throw new Error(`${url} failed: HTTP ${response.status}`);
  }
  return response;
}

async function main() {
  const releaseResponse = await request(`https://api.github.com/repos/${repo}/releases/latest`);
  const release = await releaseResponse.json();
  const assets = Array.isArray(release.assets) ? release.assets : [];
  const asset = assets.find((candidate) => assetRegex.test(candidate.name || ""));
  if (!asset) {
    throw new Error(`No matching asset in latest release ${release.tag_name || ""}`);
  }

  const assetResponse = await request(asset.browser_download_url, "application/octet-stream");
  const bytes = Buffer.from(await assetResponse.arrayBuffer());
  fs.mkdirSync(downloadDir, { recursive: true });
  fs.writeFileSync(path.join(downloadDir, asset.name), bytes);
  fs.writeFileSync(path.join(downloadDir, canonicalName), bytes);
  console.log(`Downloaded ${asset.name} as ${canonicalName}`);
}

main().catch((error) => {
  console.error(error.message || error);
  process.exit(1);
});
NODE
}

run_as_app_user() {
  if command -v runuser >/dev/null 2>&1; then
    runuser -u "$APP_USER" -- "$@"
  else
    sudo -u "$APP_USER" "$@"
  fi
}

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

PROJECT_REAL="$(realpath "$PROJECT_DIR")"
APP_REAL="$(realpath -m "$APP_DIR")"
case "$PROJECT_REAL/" in
  "$APP_REAL"/*)
    echo "Refusing unsafe deployment: APP_DIR ($APP_DIR) contains the source checkout ($PROJECT_DIR)."
    echo "Set NOVASENTINEL_CLOUD_APP_DIR to a separate runtime directory, for example /opt/$APP_NAME-runtime."
    exit 1
    ;;
esac

if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
  groupadd --system "$APP_GROUP"
fi

if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin --gid "$APP_GROUP" "$APP_USER"
fi

mkdir -p "$APP_DIR"
mkdir -p "$DATA_DIR"
mkdir -p "$DOWNLOAD_DIR"
backup_env_file "$APP_DIR/.env"

if command -v rsync >/dev/null 2>&1; then
  rsync -a \
    --delete \
    --exclude ".git" \
    --exclude ".env" \
    --exclude ".env.*" \
    --exclude "node_modules" \
    --exclude "data" \
    --exclude "*.log" \
    "$PROJECT_DIR/" "$APP_DIR/"
else
  cp -r "$PROJECT_DIR/"* "$APP_DIR/"
  rm -rf "$APP_DIR/data" 2>/dev/null || true
fi
archive_legacy_env_backups

cp -a "$PROJECT_DIR/data/"* "$DATA_DIR/" 2>/dev/null || true
if [[ -d "$APP_DIR/data" && ! -L "$APP_DIR/data" ]]; then
  cp -a "$APP_DIR/data/." "$DATA_DIR/" 2>/dev/null || true
  rm -rf "$APP_DIR/data"
fi
ln -sfn "$DATA_DIR" "$APP_DIR/data"

chown -R "$APP_USER:$APP_GROUP" "$APP_DIR" "$DATA_DIR"
chmod -R 0750 "$APP_DIR/data"
chmod +x "$APP_DIR/tools/run-premium-cloud.sh"

upsert_env "$APP_DIR/.env" HOST "$HOST"
upsert_env "$APP_DIR/.env" PORT "$PORT"
upsert_env "$APP_DIR/.env" NODE_ENV "production"
upsert_env "$APP_DIR/.env" NOVASENTINEL_PREMIUM_DB "$DB_PATH"
set_env_if_missing "$APP_DIR/.env" PUBLIC_BASE_URL "https://yourdomain.example"
set_env_if_missing "$APP_DIR/.env" STRIPE_SECRET_KEY ""
set_env_if_missing "$APP_DIR/.env" STRIPE_WEBHOOK_SECRET ""
set_env_if_missing "$APP_DIR/.env" PREMIUM_ED25519_PRIVATE_KEY_PEM ""
set_env_if_missing "$APP_DIR/.env" GITHUB_TOKEN "$GITHUB_TOKEN"
set_env_if_missing "$APP_DIR/.env" NOVASENTINEL_BACKUP_INTERVAL_HOURS "24"
set_env_if_missing "$APP_DIR/.env" NOVASENTINEL_BACKUP_RETENTION "14"
chown root:"$APP_GROUP" "$APP_DIR/.env"
chmod 0640 "$APP_DIR/.env"

installer_asset="$(latest_matching_file "NovaSentinel-Setup-*.exe" "$REPO_DIR/release" "$PROJECT_DIR/downloads" "$PROJECT_DIR/data/downloads")"
admin_console_asset="$(latest_matching_file "novasentinel-admin-console-*.zip" "$REPO_DIR/release" "$PROJECT_DIR/downloads" "$PROJECT_DIR/data/downloads")"
copy_download_asset "$installer_asset" "NovaSentinelSetup.exe"
copy_download_asset "$admin_console_asset" "NovaSentinelAdminConsole.zip"
if [[ -z "$installer_asset" ]]; then
  if ! download_github_release_asset '^NovaSentinel-Setup-.+\.exe$' "NovaSentinelSetup.exe"; then
    log "No NovaSentinel installer asset found locally or on latest GitHub Release; keeping any existing $DOWNLOAD_DIR/NovaSentinelSetup.exe"
  fi
fi
if [[ -z "$admin_console_asset" ]]; then
  if ! download_github_release_asset '^novasentinel-admin-console-.+\.zip$' "NovaSentinelAdminConsole.zip"; then
    log "No Admin Console zip asset found locally or on latest GitHub Release; keeping any existing $DOWNLOAD_DIR/NovaSentinelAdminConsole.zip"
  fi
fi
chown -R "$APP_USER:$APP_GROUP" "$DOWNLOAD_DIR"
chmod -R 0750 "$DOWNLOAD_DIR"

cat > /etc/systemd/system/$APP_NAME.service <<EOF
[Unit]
Description=NovaSentinel Premium Cloud
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/tools/run-premium-cloud.sh
EnvironmentFile=$APP_DIR/.env
Environment=NOVASENTINEL_NODE_BIN=$NODE_BIN
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

log "Initializing SQLite schema at $DB_PATH"
run_as_app_user env \
  NODE_ENV=production \
  HOST=127.0.0.1 \
  PORT=0 \
  NOVASENTINEL_PREMIUM_DB="$DB_PATH" \
  NOVASENTINEL_INIT_DB_ONLY=1 \
  "$NODE_BIN" "$APP_DIR/server.js"

if [[ ! -s "$DB_PATH" ]]; then
  echo "Database was not initialized: $DB_PATH"
  exit 1
fi

if command -v sqlite3 >/dev/null 2>&1; then
  if ! sqlite3 "$DB_PATH" "SELECT name FROM sqlite_master WHERE type='table' AND name='users';" | grep -qx users; then
    echo "Database initialized but required table 'users' is missing: $DB_PATH"
    exit 1
  fi
else
  log "sqlite3 command not found; schema was initialized by Node but table verification was skipped."
fi

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
- Downloads directory: $DOWNLOAD_DIR
- Public installer URL: /downloads/NovaSentinelSetup.exe
- Public Admin Console URL: /downloads/NovaSentinelAdminConsole.zip

You can manage with:
  systemctl status $APP_NAME
  systemctl restart $APP_NAME
  systemctl stop $APP_NAME
EOF2
