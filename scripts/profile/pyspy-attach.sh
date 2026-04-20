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

PY_VER="$(python -c 'import sys; print(f"{sys.version_info[0]}.{sys.version_info[1]}")')"
if [[ "${PY_VER}" == "3.14" ]] || [[ "${PY_VER}" > "3.14" ]]; then
    cat >&2 <<EOF
WARNING: py-spy 0.4.1 (latest on PyPI) does not yet support Python ${PY_VER}.
Attaching will fail with "No python processes found in process <pid>".
Use one of the other lenses for now:
    DECNET_PROFILE_REQUESTS=true   # pyinstrument, per-request flamegraphs
    scripts/profile/memray-api.sh  # memory allocation profiling
    scripts/profile/cprofile-cli.sh <cmd>  # deterministic CLI profiling
Track upstream: https://github.com/benfred/py-spy/releases
EOF
    exit 2
fi

echo "Attaching py-spy to PID ${PID} for ${DURATION}s -> ${OUT}"
sudo .venv/bin/py-spy record -o "${OUT}" -p "${PID}" -d "${DURATION}" --subprocesses
echo "Wrote ${OUT}"
