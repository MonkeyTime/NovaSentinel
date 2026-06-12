#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$APP_DIR"

if [[ ! -f "$APP_DIR/server.js" ]]; then
  echo "Server entrypoint missing: $APP_DIR/server.js"
  exit 1
fi

ENV_FILE="${NOVASENTINEL_ADMIN_ENV_FILE:-$APP_DIR/.env}"

if [[ -f "$ENV_FILE" ]]; then
  while IFS='=' read -r key value || [[ -n "$key" ]]; do
    key="${key%%[[:space:]]*}"
    [[ -z "$key" || "$key" == \#* ]] && continue
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"
    case "$key" in
      NODE_ENV|NOVASENTINEL_ADMIN_HOST|NOVASENTINEL_ADMIN_PORT|NOVASENTINEL_ADMIN_ALLOWED_CLOUD_HOSTS|NOVASENTINEL_ADMIN_ALLOWED_CLOUD_ORIGINS|NOVASENTINEL_ADMIN_TOKEN|NOVASENTINEL_NODE_BIN)
        export "$key=$value"
        ;;
    esac
  done < "$ENV_FILE"
fi

NODE_BIN="${NOVASENTINEL_NODE_BIN:-}"
if [[ -n "$NODE_BIN" && ! -x "$NODE_BIN" ]]; then
  echo "NOVASENTINEL_NODE_BIN is set but not executable: $NODE_BIN"
  exit 1
fi

if [[ -z "$NODE_BIN" ]]; then
  EMBEDDED_NODE="$APP_DIR/node/bin/node"
  if [[ -x "$EMBEDDED_NODE" ]]; then
    NODE_BIN="$EMBEDDED_NODE"
  elif [[ -x "$APP_DIR/node/node" ]]; then
    NODE_BIN="$APP_DIR/node/node"
  fi
fi

if [[ -z "${NODE_BIN:-}" ]]; then
  NODE_BIN="$(command -v node || true)"
fi

if [[ -z "${NODE_BIN:-}" ]]; then
  cat <<'EOF'
A Node.js runtime is required.

Options:
- Install Node.js and re-run.
- Put Node in PATH.
- Or place a portable Node binary at "node/bin/node" next to this script.
  Example (manual):
    - mkdir -p node/bin
    - cp /path/to/node node/bin/node
EOF
  exit 1
fi

export NODE_ENV="${NODE_ENV:-production}"
export NOVASENTINEL_ADMIN_HOST="${NOVASENTINEL_ADMIN_HOST:-127.0.0.1}"
export NOVASENTINEL_ADMIN_PORT="${NOVASENTINEL_ADMIN_PORT:-8790}"

echo "NovaSentinel Admin Console starting on http://${NOVASENTINEL_ADMIN_HOST}:${NOVASENTINEL_ADMIN_PORT}"
echo "Node: $NODE_BIN"
exec "$NODE_BIN" server.js
