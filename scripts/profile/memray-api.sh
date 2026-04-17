#!/usr/bin/env bash
# Run the DECNET API under memray to capture an allocation profile.
# Stop with Ctrl-C; then render with `memray flamegraph <bin>`.
set -euo pipefail

HOST="${DECNET_API_HOST:-127.0.0.1}"
PORT="${DECNET_API_PORT:-8000}"
OUT="${OUT:-profiles/memray-$(date +%s).bin}"
mkdir -p "$(dirname "$OUT")"

echo "Starting uvicorn under memray -> ${OUT}"
python -m memray run -o "${OUT}" -m uvicorn decnet.web.api:app \
    --host "${HOST}" --port "${PORT}" --log-level warning

echo "Render with: memray flamegraph ${OUT}"
