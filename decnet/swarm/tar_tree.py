# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build a gzipped tarball of the installable DECNET package for workers.

The tarball is extracted and ``pip install``-ed on each worker, so it ships
*only* what that build needs — enumerated by an INCLUDE allowlist, never a
blocklist. This is the trust-boundary rule: a bundle crossing to another host
enumerates what it carries, so a stray ``.env.local``, TLS private key, SQLite
DB, or the operator's whole working tree can never be swept in by an exclude
list that simply forgot a pattern.

``DEFAULT_INCLUDES`` is the package surface (``decnet/`` + packaging metadata);
``_HYGIENE_PATTERNS`` is a defensive second layer that drops secret-/churn-
shaped files even if one somehow lives under an included directory. Callers may
pass ``extra_excludes`` to narrow further, but cannot add anything outside the
allowlist.

Deliberately does NOT invoke git — the included dirs are taken from disk as-is.
"""
from __future__ import annotations

import fnmatch
import io
import pathlib
import tarfile
from typing import Iterable, Optional

# The ONLY top-level paths shipped to a worker: the importable package plus the
# metadata `pip install .` needs (setuptools build-meta + license-files=LICENSE).
# decnet/ carries its own package-data (templates/, canary/*). Everything else
# in the working tree — secrets, DBs, logs, the dashboard source, tests, build
# artifacts — is excluded by construction.
DEFAULT_INCLUDES = (
    "pyproject.toml",
    "LICENSE",
    "README.md",
    "decnet",
)

# Defensive hygiene applied WITHIN an included path: never ship build churn or
# anything secret-shaped, matched on the basename so it catches any nesting.
_HYGIENE_PATTERNS = (
    "*.pyc", "*.pyo",
    "*.db", "*.db-wal", "*.db-shm", "*.db-journal",
    "*.log",
    ".env", ".env.*", "*.env",
    "*.key", "*.pem", "*.crt", "*.p12", "*.pfx",
)


def _is_excluded(rel: str, patterns: Iterable[str]) -> bool:
    parts = pathlib.PurePosixPath(rel).parts
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
        # Also match the pattern against every leading subpath so a caller can
        # exclude a whole subtree without spelling out every `**/` glob.
        for i in range(1, len(parts) + 1):
            if fnmatch.fnmatch("/".join(parts[:i]), pat):
                return True
    return False


def _hygiene_skip(rel: str) -> bool:
    """True for build-churn / secret-shaped files anywhere in the tree."""
    p = pathlib.PurePosixPath(rel)
    if "__pycache__" in p.parts:
        return True
    return any(fnmatch.fnmatch(p.name, pat) for pat in _HYGIENE_PATTERNS)


def tar_working_tree(
    root: pathlib.Path,
    extra_excludes: Optional[Iterable[str]] = None,
    includes: Optional[Iterable[str]] = None,
) -> bytes:
    """Return the gzipped tarball of the installable package under ``root``.

    Only paths in ``includes`` (default :data:`DEFAULT_INCLUDES`) are walked;
    ``extra_excludes`` narrows further but can never widen the set. Entries are
    added with paths relative to ``root`` (no leading ``/``, no ``..``). The
    updater rejects unsafe paths on the receiving side.
    """
    include_roots = list(includes) if includes is not None else list(DEFAULT_INCLUDES)
    extra = list(extra_excludes or ())
    buf = io.BytesIO()

    def _admit(path: pathlib.Path) -> None:
        rel = path.relative_to(root).as_posix()
        if _hygiene_skip(rel) or _is_excluded(rel, extra):
            return
        tar.add(path, arcname=rel, recursive=False)

    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for entry in include_roots:
            base = root / entry
            if not base.exists() or base.is_symlink():
                continue
            if base.is_file():
                _admit(base)
                continue
            for path in sorted(base.rglob("*")):
                # Skip symlinks (dangling/portability) and dirs (added implicitly).
                if path.is_symlink() or path.is_dir():
                    continue
                _admit(path)

    return buf.getvalue()


def detect_git_sha(root: pathlib.Path) -> str:
    """Best-effort ``HEAD`` sha. Returns ``""`` if not a git repo."""
    head = root / ".git" / "HEAD"
    if not head.is_file():
        return ""
    try:
        ref = head.read_text().strip()
    except OSError:
        return ""
    if ref.startswith("ref: "):
        ref_path = root / ".git" / ref[5:]
        if ref_path.is_file():
            try:
                return ref_path.read_text().strip()
            except OSError:
                return ""
        return ""
    return ref
