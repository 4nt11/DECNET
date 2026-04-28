#!/usr/bin/env bash
# Start a local `decnet bus` worker for manual smoke-testing.
# Uses /tmp so it works without root and without the `decnet` POSIX group.
# Usage: scripts/bus/start.sh [heartbeat-seconds]
set -euo pipefail

SOCK="${DECNET_BUS_SOCKET:-/tmp/decnet-bus.sock}"
HEARTBEAT="${1:-3}"

echo "bus: socket=${SOCK} heartbeat=${HEARTBEAT}s  (Ctrl-C to stop)"
exec decnet bus --socket "${SOCK}" --group "" --heartbeat "${HEARTBEAT}"
