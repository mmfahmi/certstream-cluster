#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ -x "$ROOT_DIR/.venv/bin/python" ]]; then
  PYTHON="$ROOT_DIR/.venv/bin/python"
else
  PYTHON="$(command -v python3 || true)"
fi

if [[ -z "$PYTHON" ]]; then
  echo "Python 3 was not found. Create .venv and install requirements.txt." >&2
  exit 1
fi

collector_pid=""
viewer_pid=""

cleanup() {
  trap - INT TERM EXIT
  echo "Stopping local collector, viewer, and CertStream..."
  [[ -z "$collector_pid" ]] || kill "$collector_pid" 2>/dev/null || true
  [[ -z "$viewer_pid" ]] || kill "$viewer_pid" 2>/dev/null || true
  [[ -z "$collector_pid" ]] || wait "$collector_pid" 2>/dev/null || true
  [[ -z "$viewer_pid" ]] || wait "$viewer_pid" 2>/dev/null || true
  docker compose stop certstream >/dev/null 2>&1 || true
}
trap cleanup INT TERM EXIT

if ! "$PYTHON" -c 'import websocket, zstandard, tldextract, google.cloud.storage' 2>/dev/null; then
  echo "Project dependencies are missing. Run: $PYTHON -m pip install -r requirements.txt" >&2
  exit 1
fi

docker compose up -d certstream

CERTSTREAM_URL="${CERTSTREAM_URL:-ws://localhost:8081/}" \
LOCAL_BUFFER_DIR="$ROOT_DIR/data/buffer" \
FLUSH_INTERVAL_SECONDS="${FLUSH_INTERVAL_SECONDS:-30}" \
"$PYTHON" "$ROOT_DIR/collector.py" &
collector_pid=$!

"$PYTHON" "$ROOT_DIR/utils/temporal_clustering.py" "$ROOT_DIR/data/buffer" \
  --serve \
  --window-hours "${CLUSTER_WINDOW_HOURS:-1}" \
  --min-size "${CLUSTER_MIN_SIZE:-3}" \
  --output "$ROOT_DIR/data/domain-clusters.json" &
viewer_pid=$!

echo "All services are running. Open http://127.0.0.1:8765/"
echo "Collector flush interval: ${FLUSH_INTERVAL_SECONDS:-30}s. Press Ctrl-C to stop all services."

wait -n "$collector_pid" "$viewer_pid"
exit_code=$?
exit "$exit_code"
