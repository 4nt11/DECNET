# SPDX-License-Identifier: AGPL-3.0-or-later
"""Filesystem store for operator-uploaded canary blobs.

Blobs live under ``/var/lib/decnet/canary/blobs/<sha256>`` (override
via ``DECNET_CANARY_BLOB_DIR``) and are deduplicated by content hash.
The DB table :class:`decnet.web.db.models.CanaryBlob` mirrors
metadata; the bytes are read on demand at instrumentation time, so
the API process never holds large operator uploads in memory longer
than the request itself.

Refcount-aware deletion is enforced at the DB layer (see
:meth:`decnet.web.db.repository.BaseRepository.delete_canary_blob`);
this module only provides write/read/unlink primitives keyed by
sha256.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Tuple


def blob_dir() -> Path:
    """Return the on-disk root for canary blobs.

    Honors ``DECNET_CANARY_BLOB_DIR`` so tests can point at a tmp
    path.  The directory is created lazily on first write.
    """
    raw = os.environ.get("DECNET_CANARY_BLOB_DIR", "/var/lib/decnet/canary/blobs")
    return Path(raw)


def _path_for(sha256: str) -> Path:
    # Two-level fan-out (``ab/cd/abcd...``) keeps any one directory
    # from accumulating thousands of entries on busy fleets.  Same
    # shape as Git's loose-object store.
    if len(sha256) < 4:
        raise ValueError("sha256 must be at least 4 chars")
    root = blob_dir()
    return root / sha256[:2] / sha256[2:4] / sha256


def write_blob(content: bytes) -> Tuple[str, Path, int]:
    """Persist ``content`` under its sha256 path.

    Idempotent: if the target file already exists with the same
    bytes, no rewrite happens.  Returns ``(sha256, path,
    size_bytes)``.
    """
    sha = hashlib.sha256(content).hexdigest()
    target = _path_for(sha)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        # Atomic-ish: write to a temp sibling and rename.  Avoids the
        # half-written-file race a concurrent reader would otherwise
        # see if we wrote in place.
        tmp = target.with_suffix(target.suffix + ".part")
        tmp.write_bytes(content)
        os.replace(tmp, target)
    return sha, target, len(content)


def read_blob(sha256: str) -> bytes:
    """Read the bytes for a stored blob.

    Raises :class:`FileNotFoundError` when the on-disk row was unlinked
    out of band (operator pruned ``/var/lib/decnet`` by hand) — the
    caller (instrumenter dispatch) surfaces it as a 410-ish error so
    the operator can re-upload.
    """
    return _path_for(sha256).read_bytes()


def unlink_blob(sha256: str) -> bool:
    """Delete the on-disk bytes for ``sha256``.

    Returns True if a file was removed, False if it was already gone.
    The DB row deletion happens in
    :meth:`SQLModelRepository.delete_canary_blob`; this function is
    a best-effort companion called *after* the DB delete commits so
    a crash between them leaves a recoverable orphan, never a
    dangling DB reference.
    """
    target = _path_for(sha256)
    try:
        target.unlink()
    except FileNotFoundError:
        return False
    return True
