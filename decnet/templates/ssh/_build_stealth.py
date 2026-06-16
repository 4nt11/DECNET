#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Build-time helper: merge capture Python sources, XOR+gzip+base64 pack them
and the capture.sh loop, and render the final /entrypoint.sh from its
templated form.

Runs inside the Docker build. Reads from /tmp/build/, writes /entrypoint.sh.
"""

from __future__ import annotations

import base64
import gzip
import random
import sys
from pathlib import Path

BUILD = Path("/tmp/build")


def _merge_python() -> str:
    bridge = (BUILD / "syslog_bridge.py").read_text()
    emit = (BUILD / "emit_capture.py").read_text()

    def _clean(src: str) -> tuple[list[str], list[str]]:
        """Return (future_imports, other_lines) with noise stripped."""
        futures: list[str] = []
        rest: list[str] = []
        for line in src.splitlines():
            ls = line.lstrip()
            if ls.startswith("from __future__"):
                futures.append(line)
            elif ls.startswith("sys.path.insert") or ls.startswith("from syslog_bridge"):
                continue
            else:
                rest.append(line)
        return futures, rest

    b_fut, b_rest = _clean(bridge)
    e_fut, e_rest = _clean(emit)

    # Deduplicate future imports and hoist to the very top.
    seen: set[str] = set()
    futures: list[str] = []
    for line in (*b_fut, *e_fut):
        stripped = line.strip()
        if stripped not in seen:
            seen.add(stripped)
            futures.append(line)

    header = "\n".join(futures)
    body = "\n".join(b_rest) + "\n\n" + "\n".join(e_rest)
    return (header + "\n" if header else "") + body


def _pack(text: str, key: int) -> str:
    gz = gzip.compress(text.encode("utf-8"))
    xored = bytes(b ^ key for b in gz)
    return base64.b64encode(xored).decode("ascii")


def main() -> int:
    key = random.SystemRandom().randint(1, 255)

    merged_py = _merge_python()
    capture_sh = (BUILD / "capture.sh").read_text()

    emit_b64 = _pack(merged_py, key)
    relay_b64 = _pack(capture_sh, key)

    tpl = (BUILD / "entrypoint.sh").read_text()
    rendered = (
        tpl.replace("__STEALTH_KEY__", str(key))
           .replace("__EMIT_CAPTURE_B64__", emit_b64)
           .replace("__JOURNAL_RELAY_B64__", relay_b64)
    )

    for marker in ("__STEALTH_KEY__", "__EMIT_CAPTURE_B64__", "__JOURNAL_RELAY_B64__"):
        if marker in rendered:
            print(f"build: placeholder {marker} still present after render", file=sys.stderr)
            return 1

    Path("/entrypoint.sh").write_text(rendered)
    Path("/entrypoint.sh").chmod(0o755)
    return 0


if __name__ == "__main__":
    sys.exit(main())
