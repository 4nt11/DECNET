# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Helpers for dropping root ownership on files created during privileged
operations (e.g. `sudo decnet deploy` needs root for MACVLAN, but its log
files should be owned by the invoking user so a subsequent non-root
`decnet api` can append to them).

When sudo invokes a process, it sets SUDO_UID / SUDO_GID in the
environment to the original user's IDs. We use those to chown files
back after creation.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


def _sudo_ids() -> Optional[tuple[int, int]]:
    """Return (uid, gid) of the sudo-invoking user, or None when the
    process was not launched via sudo / the env vars are missing."""
    raw_uid = os.environ.get("SUDO_UID")
    raw_gid = os.environ.get("SUDO_GID")
    if not raw_uid or not raw_gid:
        return None
    try:
        return int(raw_uid), int(raw_gid)
    except ValueError:
        return None


def chown_to_invoking_user(path: str | os.PathLike[str]) -> None:
    """Best-effort chown of *path* to the sudo-invoking user.

    No-op when:
      * not running as root (nothing to drop),
      * not launched via sudo (no SUDO_UID/SUDO_GID),
      * the path does not exist,
      * chown fails (logged-only — never raises).
    """
    if os.geteuid() != 0:
        return
    ids = _sudo_ids()
    if ids is None:
        return
    uid, gid = ids
    p = Path(path)
    if not p.exists():
        return
    try:
        os.chown(p, uid, gid)
    except OSError:
        # Best-effort; a failed chown is not fatal to logging.
        pass


def chown_tree_to_invoking_user(root: str | os.PathLike[str]) -> None:
    """Apply :func:`chown_to_invoking_user` to *root* and every file/dir
    beneath it. Used for parent directories that we just created with
    ``mkdir(parents=True)`` as root."""
    if os.geteuid() != 0 or _sudo_ids() is None:
        return
    root_path = Path(root)
    if not root_path.exists():
        return
    chown_to_invoking_user(root_path)
    for entry in root_path.rglob("*"):
        chown_to_invoking_user(entry)
