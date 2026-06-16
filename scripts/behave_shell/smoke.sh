#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
### Usage: scripts/behave_shell/smoke.sh [BEHAVE_CALIBRATION_DIR]
#
# BEHAVE-INTEGRATION Phase 6 — offline replay smoke test.
#
# Runs the production handler
# (`decnet.profiler.behave_shell._handler.handle_session_ended`) against
# each of the five 2026-05-02 calibration shards, asserts every session
# in every shard produces ≥ 1 observation, and prints a per-class
# summary.
#
# This is the **offline** half of Phase 6. The **live-decky** half is
# documented in `scripts/behave_shell/README.md` — that one needs a
# real PTY round-trip and stays manual.
#
# Argument:
#   $1   Optional path to the directory holding
#        sessions-2026-05-02-*.jsonl. Defaults to
#        ../BEHAVE/prototype_extractors/shell relative to this repo.
#
# Exits 0 on full pass, 1 on any class regression, 2 on bad input.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"
DEFAULT_DIR="${REPO_ROOT}/../BEHAVE/prototype_extractors/shell"
CALIB_DIR="${1:-${DEFAULT_DIR}}"

if [[ ! -d "${CALIB_DIR}" ]]; then
    echo "smoke: FAIL — calibration dir not found: ${CALIB_DIR}" >&2
    echo "smoke: pass it as \$1 or symlink it next to DECNET/" >&2
    exit 2
fi

# Auto-activate the project venv so the script works whether or not
# the caller already sourced it (mirrors the .311 convention from the
# pre-commit hook).
if [[ -d "${REPO_ROOT}/.311" ]]; then
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/.311/bin/activate"
fi

# Force sqlite so the smoke doesn't depend on a running mysql.
export DECNET_DB_TYPE="sqlite"

# Suppress the verbose decnet logger so the per-class summary lines
# stay readable. ANTI's developer log has DEBUG enabled via env; mute
# at the smoke entrypoint.
export DECNET_LOG_LEVEL="${DECNET_LOG_LEVEL:-WARNING}"
unset DECNET_DEVELOPER_MODE 2>/dev/null || true

declare -a SHARDS=(
    "sessions-2026-05-02.jsonl|HUMAN"
    "sessions-2026-05-02-with-llm.jsonl|YOU-sim"
    "sessions-2026-05-02-new.jsonl|LW-sim"
    "sessions-2026-05-02-with-claude.jsonl|CLAUDE-FF"
    "sessions-2026-05-02-closed-loop.jsonl|CLAUDE-CL"
)

LOGDIR="$(mktemp -d -t behave-smoke.XXXXXX)"
trap 'rm -rf "${LOGDIR}"' EXIT

echo "smoke: replaying ${#SHARDS[@]} calibration classes from ${CALIB_DIR}"
echo "smoke: per-class logs in ${LOGDIR}"
echo

failed=0
for entry in "${SHARDS[@]}"; do
    fn="${entry%%|*}"
    label="${entry##*|}"
    shard="${CALIB_DIR}/${fn}"
    if [[ ! -f "${shard}" ]]; then
        echo "[${label}] SKIP — shard not present: ${shard}" >&2
        continue
    fi
    log="${LOGDIR}/${label}.log"
    set +e
    python "${HERE}/replay_calibration.py" \
        --shard "${shard}" --label "${label}" >"${log}" 2>&1
    rc=$?
    set -e
    # Surface the summary lines (everything starting with '['). They go
    # to stdout in the python tool; stderr noise stays in the log file.
    grep -E '^\[' "${log}" || true
    if [[ "${rc}" -ne 0 ]]; then
        failed=$((failed + 1))
        echo "[${label}] (full log: ${log})" >&2
    fi
done

echo
if [[ "${failed}" -gt 0 ]]; then
    echo "smoke: FAIL — ${failed} class(es) regressed" >&2
    exit 1
fi
echo "smoke: OK — all classes emit observations end-to-end"
