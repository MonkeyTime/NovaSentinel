#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$APP_DIR"

if [[ ! -f "$APP_DIR/server.js" ]]; then
  echo "Server entrypoint missing: $APP_DIR/server.js"
  exit 1
fi

ENV_FILE="${NOVASENTINEL_CLOUD_ENV_FILE:-$APP_DIR/.env}"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
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
  else
    NODE_BIN="$(command -v node || true)"
  fi
fi

if [[ -z "${NODE_BIN:-}" ]]; then
  echo "Node.js runtime required."
  echo "Install Node.js, make it available in PATH, or set NOVASENTINEL_NODE_BIN."
  exit 1
fi

export NODE_ENV="${NODE_ENV:-production}"
if [[ -n "${NOVASENTINEL_PREMIUM_DB:-}" ]]; then
  mkdir -p "$(dirname "$NOVASENTINEL_PREMIUM_DB")"
fi

if [[ -z "${HOST:-}" ]]; then
  export HOST="${HOST:-127.0.0.1}"
fi
if [[ -z "${PORT:-}" ]]; then
  export PORT=8780
fi

echo "NovaSentinel Enterprise Cloud starting on http://${HOST}:${PORT}"
echo "Node: $NODE_BIN"
exec "$NODE_BIN" server.js
