#!/usr/bin/env bash
# Run a `decnet` subcommand under cProfile and write a .prof file for snakeviz.
# Usage: scripts/profile/cprofile-cli.sh services
#        scripts/profile/cprofile-cli.sh status
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <decnet-subcommand> [args...]" >&2
    exit 1
fi

OUT="${OUT:-profiles/cprofile-$(date +%s).prof}"
mkdir -p "$(dirname "$OUT")"

python -m cProfile -o "${OUT}" -m decnet.cli "$@"
echo "Wrote ${OUT}"
echo "View with: snakeviz ${OUT}"
