#!/usr/bin/env bash
set -euo pipefail

APP_NAME="${NOVASENTINEL_CLOUD_APP_NAME:-novasentinel-premium-cloud}"
REPO_URL="${NOVASENTINEL_REPO_URL:-https://github.com/MonkeyTime/NovaSentinel.git}"
REPO_BRANCH="${NOVASENTINEL_REPO_BRANCH:-main}"
SOURCE_DIR="${NOVASENTINEL_SOURCE_DIR:-/opt/$APP_NAME/source}"
RUNTIME_DIR="${NOVASENTINEL_CLOUD_APP_DIR:-/opt/$APP_NAME-runtime}"
APP_USER="${NOVASENTINEL_CLOUD_APP_USER:-novasentinel}"
HOST="${NOVASENTINEL_CLOUD_HOST:-127.0.0.1}"
PORT="${NOVASENTINEL_CLOUD_PORT:-8780}"
DOMAIN="${NOVASENTINEL_DOMAIN:-}"
LETSENCRYPT="${NOVASENTINEL_ENABLE_LETSENCRYPT:-0}"
LETSENCRYPT_EMAIL="${NOVASENTINEL_LETSENCRYPT_EMAIL:-}"
GITHUB_REPO="${NOVASENTINEL_GITHUB_REPO:-MonkeyTime/NovaSentinel}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

log() {
  printf '\n[NovaSentinel bootstrap] %s\n' "$*"
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash premium_cloud/tools/bootstrap-ubuntu-vps.sh"
    exit 1
  fi
}

install_node_24() {
  local current_major="0"
  if command -v node >/dev/null 2>&1; then
    current_major="$(node -p "Number(process.versions.node.split('.')[0])" 2>/dev/null || echo 0)"
  fi
  if [[ "$current_major" -ge 24 ]]; then
    log "Node.js $(node -v) already available."
    return
  fi

  log "Installing Node.js 24.x."
  curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
  apt-get install -y nodejs
  node -v
}

prepare_source() {
  log "Preparing source checkout in $SOURCE_DIR."
  mkdir -p "$(dirname "$SOURCE_DIR")"
  if [[ -d "$SOURCE_DIR/.git" ]]; then
    git -C "$SOURCE_DIR" fetch origin "$REPO_BRANCH"
    git -C "$SOURCE_DIR" checkout "$REPO_BRANCH"
    git -C "$SOURCE_DIR" pull --ff-only origin "$REPO_BRANCH"
  else
    rm -rf "$SOURCE_DIR"
    git clone --branch "$REPO_BRANCH" "$REPO_URL" "$SOURCE_DIR"
  fi
}

deploy_app() {
  log "Deploying Enterprise Cloud runtime."
  NOVASENTINEL_CLOUD_APP_NAME="$APP_NAME" \
  NOVASENTINEL_CLOUD_APP_DIR="$RUNTIME_DIR" \
  NOVASENTINEL_CLOUD_APP_USER="$APP_USER" \
  NOVASENTINEL_CLOUD_HOST="$HOST" \
  NOVASENTINEL_CLOUD_PORT="$PORT" \
  NOVASENTINEL_GITHUB_REPO="$GITHUB_REPO" \
  GITHUB_TOKEN="$GITHUB_TOKEN" \
    bash "$SOURCE_DIR/premium_cloud/tools/deploy-debian.sh"
}

configure_nginx() {
  if [[ -z "$DOMAIN" ]]; then
    log "NOVASENTINEL_DOMAIN is empty; skipping Nginx virtual host creation."
    return
  fi

  log "Configuring Nginx reverse proxy for $DOMAIN."
  cat > "/etc/nginx/sites-available/$APP_NAME" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;

    client_max_body_size 350m;

    location ~ /\.(?!well-known/) {
        return 404;
    }

    location ~* \.(env|bak|db|sqlite|sqlite3|pem|key|log|old|orig|save|swp)$ {
        return 404;
    }

    location ~* ^/(data|backups|release_uploads|node_modules|\.git)(/|$) {
        return 404;
    }

    location / {
        proxy_pass http://$HOST:$PORT;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;
    }
}
EOF
  ln -sfn "/etc/nginx/sites-available/$APP_NAME" "/etc/nginx/sites-enabled/$APP_NAME"
  nginx -t
  systemctl enable nginx
  systemctl reload nginx
}

configure_letsencrypt() {
  if [[ "$LETSENCRYPT" != "1" || -z "$DOMAIN" ]]; then
    return
  fi
  if [[ -z "$LETSENCRYPT_EMAIL" ]]; then
    echo "NOVASENTINEL_ENABLE_LETSENCRYPT=1 requires NOVASENTINEL_LETSENCRYPT_EMAIL."
    exit 1
  fi

  log "Installing Let's Encrypt certificate for $DOMAIN."
  apt-get install -y certbot python3-certbot-nginx
  certbot --nginx \
    --non-interactive \
    --agree-tos \
    --redirect \
    --email "$LETSENCRYPT_EMAIL" \
    -d "$DOMAIN"
}

print_summary() {
  log "Deployment completed."
  cat <<EOF
Runtime:
  $RUNTIME_DIR

Data:
  /var/lib/$APP_NAME/premium_cloud.sqlite3
  /var/lib/$APP_NAME/downloads/NovaSentinelSetup.exe
  /var/lib/$APP_NAME/downloads/NovaSentinelAdminConsole.zip

Service:
  systemctl status $APP_NAME --no-pager --lines=30
  journalctl -u $APP_NAME --no-pager -n 80

Health:
  curl -s http://$HOST:$PORT/api/health
  curl -I http://$HOST:$PORT/downloads/NovaSentinelSetup.exe
  curl -I http://$HOST:$PORT/downloads/NovaSentinelAdminConsole.zip
EOF
  if [[ -n "$DOMAIN" ]]; then
    cat <<EOF

Public:
  http://$DOMAIN
EOF
    if [[ "$LETSENCRYPT" == "1" ]]; then
      cat <<EOF
  https://$DOMAIN
EOF
    fi
  fi
}

main() {
  require_root
  export DEBIAN_FRONTEND=noninteractive

  log "Installing Ubuntu packages."
  apt-get update
  apt-get install -y ca-certificates curl git nginx rsync sqlite3

  install_node_24
  prepare_source
  deploy_app
  configure_nginx
  configure_letsencrypt
  print_summary
}

main "$@"
