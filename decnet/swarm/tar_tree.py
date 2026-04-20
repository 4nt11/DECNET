"""Build a gzipped tarball of the master's working tree for pushing to workers.

Always excludes the obvious large / secret / churn paths: ``.venv/``,
``__pycache__/``, ``.git/``, ``wiki-checkout/``, ``*.db*``, ``*.log``. The
caller can supply additional exclude globs.

Deliberately does NOT invoke git — the tree is what the operator has on
disk (staged + unstaged + untracked). That's the whole point; the scp
workflow we're replacing also shipped the live tree.
"""
from __future__ import annotations

import fnmatch
import io
import pathlib
import tarfile
from typing import Iterable, Optional

DEFAULT_EXCLUDES = (
    ".venv", ".venv/*",
    "**/.venv/*",
    "__pycache__", "**/__pycache__", "**/__pycache__/*",
    ".git", ".git/*",
    "wiki-checkout", "wiki-checkout/*",
    "*.pyc", "*.pyo",
    "*.db", "*.db-wal", "*.db-shm",
    "*.log",
    ".pytest_cache", ".pytest_cache/*",
    ".mypy_cache", ".mypy_cache/*",
    ".tox", ".tox/*",
    "*.egg-info", "*.egg-info/*",
    "decnet-state.json",
    "master.log", "master.json",
    "decnet.db*",
)


def _is_excluded(rel: str, patterns: Iterable[str]) -> bool:
    parts = pathlib.PurePosixPath(rel).parts
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
        # Also match the pattern against every leading subpath — this is
        # what catches nested `.venv/...` without forcing callers to spell
        # out every `**/` glob.
        for i in range(1, len(parts) + 1):
            if fnmatch.fnmatch("/".join(parts[:i]), pat):
                return True
    return False


def tar_working_tree(
    root: pathlib.Path,
    extra_excludes: Optional[Iterable[str]] = None,
) -> bytes:
    """Return the gzipped tarball bytes of ``root``.

    Entries are added with paths relative to ``root`` (no leading ``/``,
    no ``..``). The updater rejects unsafe paths on the receiving side.
    """
    patterns = list(DEFAULT_EXCLUDES) + list(extra_excludes or ())
    buf = io.BytesIO()

    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for path in sorted(root.rglob("*")):
            rel = path.relative_to(root).as_posix()
            if _is_excluded(rel, patterns):
                continue
            if path.is_symlink():
                # Symlinks inside a repo tree are rare and often break
                # portability; skip them rather than ship dangling links.
                continue
            if path.is_dir():
                continue
            tar.add(path, arcname=rel, recursive=False)

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
