#!/usr/bin/env bash
# Mutator-family topic smoke test: boots a bus worker, subscribes to
# `topology.>`, publishes one event per mutation-lifecycle state
# (enqueued → applying → applied) plus a topology.status transition,
# and verifies each lands on the subscriber.
#
# This is a cheap E2E for the topic hierarchy wired into the mutator
# and SSE route — the full DB + mutator + API loop is exercised by the
# pytest suite under tests/topology/ and tests/api/topology/.
#
# Usage: scripts/bus/smoke-mutator.sh
set -euo pipefail

SOCK="$(mktemp -u -t decnet-bus-mut-smoke.XXXXXX.sock)"
export DECNET_BUS_SOCKET="${SOCK}"
LOGDIR="$(mktemp -d -t decnet-bus-mut-smoke.XXXXXX)"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TID="smoke-$(date +%s)"

cleanup() {
    kill "${SUB_PID:-0}" 2>/dev/null || true
    kill "${WORKER_PID:-0}" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -f "${SOCK}"
    rm -rf "${LOGDIR}"
}
trap cleanup EXIT

echo "smoke-mutator: socket=${SOCK} topology=${TID}"

decnet bus --socket "${SOCK}" --group "" --heartbeat 5 \
    > "${LOGDIR}/worker.log" 2>&1 &
WORKER_PID=$!

for _ in {1..40}; do
    [[ -S "${SOCK}" ]] && break
    sleep 0.05
done
if [[ ! -S "${SOCK}" ]]; then
    echo "smoke-mutator: FAIL — bus worker never created ${SOCK}" >&2
    cat "${LOGDIR}/worker.log" >&2
    exit 1
fi

python "${HERE}/sub.py" 'topology.>' > "${LOGDIR}/sub.log" 2>&1 &
SUB_PID=$!

sleep 0.3

publish() {
    local topic="$1" payload="$2"
    python "${HERE}/pub.py" "${topic}" "${payload}" >/dev/null
}

publish "topology.${TID}.mutation.enqueued"  '{"mutation_id": "m1", "op": "add_lan"}'
publish "topology.${TID}.mutation.applying"  '{"mutation_id": "m1", "op": "add_lan"}'
publish "topology.${TID}.mutation.applied"   '{"mutation_id": "m1", "op": "add_lan"}'
publish "topology.${TID}.status"             '{"state": "degraded", "reason": "smoke"}'

expected=(
    "topology.${TID}.mutation.enqueued"
    "topology.${TID}.mutation.applying"
    "topology.${TID}.mutation.applied"
    "topology.${TID}.status"
)

for _ in {1..60}; do
    missing=0
    for topic in "${expected[@]}"; do
        if ! grep -q "${topic}" "${LOGDIR}/sub.log"; then
            missing=1
            break
        fi
    done
    [[ "${missing}" -eq 0 ]] && break
    sleep 0.05
done

for topic in "${expected[@]}"; do
    if ! grep -q "${topic}" "${LOGDIR}/sub.log"; then
        echo "smoke-mutator: FAIL — missing ${topic}" >&2
        echo "--- worker.log ---" >&2; cat "${LOGDIR}/worker.log" >&2
        echo "--- sub.log ---"    >&2; cat "${LOGDIR}/sub.log"    >&2
        exit 1
    fi
done

echo "smoke-mutator: OK — all 4 mutator-family events delivered"
grep -E 'mutation|status' "${LOGDIR}/sub.log" || true
