#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Open the newest profile artifact in the right viewer.
#
# Usage:
#   scripts/profile/view.sh                 # newest file in ./profiles/
#   scripts/profile/view.sh <file>          # explicit path
#   scripts/profile/view.sh cprofile        # newest .prof
#   scripts/profile/view.sh memray          # newest memray .bin
#   scripts/profile/view.sh pyspy           # newest .svg
#   scripts/profile/view.sh pyinstrument    # newest pyinstrument .html
#
# Memray viewer override:
#   VIEW=flamegraph|table|tree|stats|summary  (default: flamegraph)
#   VIEW=leaks   (render flamegraph with --leaks filter)
set -euo pipefail

DIR="${DIR:-profiles}"
VIEW="${VIEW:-flamegraph}"

if [[ ! -d "${DIR}" ]]; then
    echo "No ${DIR}/ directory yet — run one of the profile scripts first." >&2
    exit 1
fi

pick_newest() {
    local pattern="$1"
    find "${DIR}" -maxdepth 1 -type f -name "${pattern}" -printf '%T@ %p\n' 2>/dev/null \
        | sort -n | tail -n 1 | cut -d' ' -f2-
}

TARGET=""
case "${1:-}" in
    "")           TARGET="$(pick_newest '*')" ;;
    cprofile)     TARGET="$(pick_newest '*.prof')" ;;
    memray)       TARGET="$(pick_newest 'memray-*.bin')" ;;
    pyspy)        TARGET="$(pick_newest 'pyspy-*.svg')" ;;
    pyinstrument) TARGET="$(find "${DIR}" -maxdepth 1 -type f -name '*.html' \
                       ! -name 'memray-*' -printf '%T@ %p\n' 2>/dev/null \
                       | sort -n | tail -n 1 | cut -d' ' -f2-)" ;;
    *)            TARGET="$1" ;;
esac

if [[ -z "${TARGET}" || ! -f "${TARGET}" ]]; then
    echo "No matching profile artifact found." >&2
    exit 1
fi

echo "Opening ${TARGET}"

case "${TARGET}" in
    *.prof)
        exec snakeviz "${TARGET}"
        ;;
    *memray*.bin|*.bin)
        case "${VIEW}" in
            leaks)    exec memray flamegraph --leaks -f "${TARGET}" ;;
            flamegraph|table) exec memray "${VIEW}" -f "${TARGET}" ;;
            tree|stats|summary) exec memray "${VIEW}" "${TARGET}" ;;
            *) echo "Unknown VIEW=${VIEW}" >&2; exit 1 ;;
        esac
        ;;
    *.svg|*.html)
        exec xdg-open "${TARGET}"
        ;;
    *)
        echo "Don't know how to view ${TARGET}" >&2
        exit 1
        ;;
esac
