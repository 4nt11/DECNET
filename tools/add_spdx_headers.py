#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Prepend SPDX-License-Identifier headers to every source file in DECNET.

One-shot tool. Safe to re-run (idempotent: skips files that already have SPDX).

Rules:
  - .py / .sh         -> '# SPDX-License-Identifier: AGPL-3.0-or-later'
  - .ts / .tsx / .js / .jsx
                      -> '// SPDX-License-Identifier: AGPL-3.0-or-later'
  - .css              -> '/* SPDX-License-Identifier: AGPL-3.0-or-later */'

Shebang preservation:
  - If line 1 starts with '#!', the SPDX header is inserted on line 2.
  - For .py, if a coding declaration (PEP 263) follows the shebang or sits on
    line 1/2, the SPDX header is inserted AFTER it.

Skips: .venv, .311, .git, node_modules, __pycache__, .mypy_cache, dist, build,
       .next, artifacts, bait, .benchmarks, .pytest_cache, decnet.egg-info,
       wiki-checkout, and any file matching --exclude.

Idempotency: a file containing 'SPDX-License-Identifier' anywhere in its first
12 lines is left untouched.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SPDX_ID = "SPDX-License-Identifier: AGPL-3.0-or-later"

COMMENT_BY_EXT: dict[str, str] = {
    ".py": f"# {SPDX_ID}",
    ".sh": f"# {SPDX_ID}",
    ".ts": f"// {SPDX_ID}",
    ".tsx": f"// {SPDX_ID}",
    ".js": f"// {SPDX_ID}",
    ".jsx": f"// {SPDX_ID}",
    ".css": f"/* {SPDX_ID} */",
}

SKIP_DIRS = {
    ".venv",
    ".venv_test",
    ".311",
    ".git",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".benchmarks",
    "site-packages",
    "dist",
    "build",
    ".next",
    "artifacts",
    "bait",
    "decnet.egg-info",
    "wiki-checkout",
}

CODING_RE = re.compile(rb"coding[=:]\s*([-\w.]+)")


def is_skipped(path: Path, root: Path) -> bool:
    try:
        rel_parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in SKIP_DIRS for part in rel_parts)


def has_spdx(head_lines: list[bytes]) -> bool:
    for line in head_lines[:12]:
        if b"SPDX-License-Identifier" in line:
            return True
    return False


def compute_insert_index(lines: list[bytes], ext: str) -> int:
    """Return the index where the SPDX line should be inserted."""
    idx = 0
    if lines and lines[0].startswith(b"#!"):
        idx = 1
    if ext == ".py":
        # PEP 263 allows coding decl on line 1 or 2.
        if idx < len(lines) and CODING_RE.search(lines[idx]):
            idx += 1
    return idx


def process_file(path: Path, *, dry_run: bool) -> str:
    ext = path.suffix
    header = COMMENT_BY_EXT.get(ext)
    if header is None:
        return "skip-ext"

    try:
        raw = path.read_bytes()
    except OSError as e:
        return f"error:{e}"

    # Preserve trailing-newline state.
    had_trailing_nl = raw.endswith(b"\n")
    lines = raw.split(b"\n")
    # If file ended with \n, split produced a trailing empty element; drop it
    # for processing and restore at write time.
    if had_trailing_nl and lines and lines[-1] == b"":
        lines.pop()

    if has_spdx(lines):
        return "already"

    insert_at = compute_insert_index(lines, ext)
    new_lines = lines[:insert_at] + [header.encode("utf-8")] + lines[insert_at:]

    out = b"\n".join(new_lines)
    if had_trailing_nl or out and not out.endswith(b"\n"):
        out += b"\n"

    if dry_run:
        return "would-add"

    path.write_bytes(out)
    return "added"


def iter_targets(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix not in COMMENT_BY_EXT:
            continue
        if is_skipped(p, root):
            continue
        out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="Repo root (default: cwd)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    targets = iter_targets(root)

    counts: dict[str, int] = {}
    samples: dict[str, list[Path]] = {}
    for p in targets:
        status = process_file(p, dry_run=args.dry_run)
        counts[status] = counts.get(status, 0) + 1
        samples.setdefault(status, []).append(p)

    print(f"root: {root}")
    print(f"total candidates: {len(targets)}")
    for status, n in sorted(counts.items()):
        print(f"  {status}: {n}")
        for s in samples[status][:3]:
            print(f"      e.g. {s.relative_to(root)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
