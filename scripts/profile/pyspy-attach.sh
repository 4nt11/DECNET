#!/usr/bin/env bash
# Attach py-spy to the running DECNET uvicorn worker(s) and record a flamegraph.
# Requires sudo on Linux because of kernel.yama.ptrace_scope=1 by default.
set -euo pipefail

DURATION="${DURATION:-30}"
OUT="${OUT:-profiles/pyspy-$(date +%s).svg}"
mkdir -p "$(dirname "$OUT")"

PID="$(pgrep -f 'uvicorn decnet.web.api' | head -n 1 || true)"
if [[ -z "${PID}" ]]; then
    echo "No uvicorn worker found. Start the API first (e.g. 'decnet deploy ...')." >&2
    exit 1
fi

echo "Attaching py-spy to PID ${PID} for ${DURATION}s -> ${OUT}"
sudo py-spy record -o "${OUT}" -p "${PID}" -d "${DURATION}" --subprocesses
echo "Wrote ${OUT}"
