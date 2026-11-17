#!/usr/bin/env bash

set -u

WORKSPACE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DISPTCHR_DIR="$WORKSPACE_DIR/DISPTCHR"
PANEL_DIR="$WORKSPACE_DIR/disptchr-panel"
LOG_DIR="$WORKSPACE_DIR/work/dev-logs"
PIDS=()

mkdir -p "$LOG_DIR"

require_directory() {
  if [ ! -d "$1" ]; then
    echo "Missing required repository: $1" >&2
    exit 1
  fi
}

port_is_open() {
  lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

start_service() {
  local name="$1"
  local port="$2"
  local directory="$3"
  shift 3

  if port_is_open "$port"; then
    echo "✓ $name already running on port $port"
    return
  fi

  (
    cd "$directory" || exit 1
    exec "$@"
  ) >"$LOG_DIR/$name.log" 2>&1 &

  local pid=$!
  PIDS+=("$pid")
  echo "→ Starting $name on port $port (log: work/dev-logs/$name.log)"
}

cleanup() {
  if [ "${#PIDS[@]}" -gt 0 ]; then
    echo
    echo "Stopping combined development services..."
    for pid in "${PIDS[@]}"; do
      kill "$pid" >/dev/null 2>&1 || true
    done
    wait "${PIDS[@]}" 2>/dev/null || true
  fi
}

trap cleanup INT TERM EXIT

require_directory "$DISPTCHR_DIR/.git"
require_directory "$PANEL_DIR/.git"

if [ ! -d "$DISPTCHR_DIR/frontend/node_modules" ]; then
  echo "DISPTCHR frontend dependencies are missing. Run:"
  echo "  cd DISPTCHR/frontend && corepack yarn install --frozen-lockfile"
  exit 1
fi

if [ ! -d "$DISPTCHR_DIR/manager-portal/node_modules" ]; then
  echo "DISPTCHR manager portal dependencies are missing. Run:"
  echo "  cd DISPTCHR/manager-portal && npm ci"
  exit 1
fi

if [ ! -d "$PANEL_DIR/node_modules" ]; then
  echo "Disptchr Panel dependencies are missing. Run:"
  echo "  cd disptchr-panel && npm install"
  exit 1
fi

start_service "employee-app" 8080 "$DISPTCHR_DIR/frontend" env CI=1 corepack yarn web --port 8080
start_service "manager-portal" 8081 "$DISPTCHR_DIR/manager-portal" npm run dev
start_service "control-panel" 3000 "$PANEL_DIR" npm run dev -- --hostname 127.0.0.1

if [ -f "$DISPTCHR_DIR/backend/.env" ]; then
  if [ -x "$DISPTCHR_DIR/.venv/bin/uvicorn" ]; then
    start_service "api" 8000 "$DISPTCHR_DIR/backend" "$DISPTCHR_DIR/.venv/bin/uvicorn" server:app --host 127.0.0.1 --port 8000 --reload
  elif command -v uvicorn >/dev/null 2>&1; then
    start_service "api" 8000 "$DISPTCHR_DIR/backend" uvicorn server:app --host 127.0.0.1 --port 8000 --reload
  else
    echo "! Backend .env exists, but uvicorn is not installed; API was not started."
  fi
else
  echo "! DISPTCHR API not started: backend/.env is not configured."
fi

echo
echo "DISPTCHR development workspace"
echo "  Employee app:  http://127.0.0.1:8080"
echo "  Manager portal: http://127.0.0.1:8081/manager/"
echo "  Control panel:  http://127.0.0.1:3000"
echo
echo "Press Control-C to stop services started by this launcher."

if [ "${#PIDS[@]}" -eq 0 ]; then
  exit 0
fi

wait
