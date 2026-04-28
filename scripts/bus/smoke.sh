#!/usr/bin/env bash
# End-to-end bus smoke test: boots a worker, subscribes, publishes,
# verifies the event lands, tears everything down. Exits non-zero if
# anything misbehaves.
#
# Usage: scripts/bus/smoke.sh
set -euo pipefail

SOCK="$(mktemp -u -t decnet-bus-smoke.XXXXXX.sock)"
export DECNET_BUS_SOCKET="${SOCK}"
LOGDIR="$(mktemp -d -t decnet-bus-smoke.XXXXXX)"
trap 'rm -f "${SOCK}"; rm -rf "${LOGDIR}"' EXIT

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "smoke: socket=${SOCK}"

decnet bus --socket "${SOCK}" --group "" --heartbeat 1 \
    > "${LOGDIR}/worker.log" 2>&1 &
WORKER_PID=$!
trap 'kill ${WORKER_PID} 2>/dev/null || true; wait ${WORKER_PID} 2>/dev/null || true; rm -f "${SOCK}"; rm -rf "${LOGDIR}"' EXIT

# Wait for the socket to exist.
for _ in {1..40}; do
    [[ -S "${SOCK}" ]] && break
    sleep 0.05
done
if [[ ! -S "${SOCK}" ]]; then
    echo "smoke: FAIL — worker never created ${SOCK}" >&2
    cat "${LOGDIR}/worker.log" >&2
    exit 1
fi

# Subscriber in the background, redirected to a file we can tail.
python "${HERE}/sub.py" 'topology.>' > "${LOGDIR}/sub.log" 2>&1 &
SUB_PID=$!
trap 'kill ${SUB_PID} 2>/dev/null || true; kill ${WORKER_PID} 2>/dev/null || true; wait 2>/dev/null || true; rm -f "${SOCK}"; rm -rf "${LOGDIR}"' EXIT

# Give the SUB frame a tick to register.
sleep 0.3

python "${HERE}/pub.py" topology.abc.status '{"state": "active"}' >/dev/null

# Wait up to 2s for the event to show up.
for _ in {1..40}; do
    if grep -q 'topology.abc.status' "${LOGDIR}/sub.log"; then
        echo "smoke: OK — subscriber received event"
        grep 'topology.abc.status' "${LOGDIR}/sub.log"
        exit 0
    fi
    sleep 0.05
done

echo "smoke: FAIL — subscriber never saw the event" >&2
echo "--- worker.log ---" >&2; cat "${LOGDIR}/worker.log" >&2
echo "--- sub.log ---"    >&2; cat "${LOGDIR}/sub.log"    >&2
exit 1
