# SPDX-License-Identifier: AGPL-3.0-or-later
"""Global persona pool — non-topology deckies.

DECNET runs in three deployment shapes that emit running deckies:

* **MazeNET topologies**       — each topology owns its own
  :attr:`Topology.email_personas` JSON list; consumers walk from the
  decky back to its parent topology row.
* **Unihost fleet**            — MACVLAN/IPVLAN deckies that have no
  parent topology row at all.  They share one host-wide pool.
* **SWARM shards**             — DeckyShard rows on enrolled workers.
  Same shape as fleet for realism purposes (no parent topology row),
  so they read the same global pool.

This module owns the global pool: a JSON file on disk that operators
populate via ``decnet realism import-personas <file>`` (or by editing
the file directly).  The file is loaded lazily on first read and
re-loaded on mtime change so a CLI import takes effect for the running
worker without a restart.

Path resolution order:

1. ``DECNET_REALISM_PERSONAS`` environment variable — explicit override.
2. ``/etc/decnet/email_personas.json`` — canonical master path; this is
   what ``decnet init`` will eventually own.  Filename retained
   (``email_personas.json``) because the on-disk schema hasn't changed
   and operators may already have committed copies.
3. ``~/.decnet/email_personas.json`` — dev fallback so a developer can
   exercise consumers without root or ``decnet init``.

When the file is missing / empty / unparseable, the pool is empty and
consumers skip fleet/shard deckies the same way they skip a topology
with too few personas.  No silent fallback to dummy personas; silence
is correct when there's no opinion to convey.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Optional

from decnet.logging import get_logger
from decnet.realism.personas import EmailPersona, parse_personas

logger = get_logger("realism.personas_pool")

_ENV_VAR = "DECNET_REALISM_PERSONAS"
_SYSTEM_PATH = Path("/etc/decnet/email_personas.json")


def _user_path() -> Path:
    return Path(os.path.expanduser("~/.decnet/email_personas.json"))


def resolve_path() -> Path:
    """Return the path the global pool would load from right now.

    The file may not exist; callers are expected to handle that.  The
    function is pure (no I/O) so the ``decnet realism import-personas``
    CLI can ask "where would I write to?" without touching the disk.
    """
    override = os.environ.get(_ENV_VAR, "").strip()
    if override:
        return Path(override)
    if _SYSTEM_PATH.exists():
        return _SYSTEM_PATH
    # ``/etc/decnet`` exists on a fully-provisioned host (post ``decnet
    # init``) but may be read-only for the API user on dev boxes — fall
    # back to the user path when the directory isn't writable so a fresh
    # PUT lands somewhere instead of erroring out.  We only do this when
    # the system file doesn't exist yet; once it does, it's authoritative.
    if _SYSTEM_PATH.parent.exists() and os.access(_SYSTEM_PATH.parent, os.W_OK):
        return _SYSTEM_PATH
    return _user_path()


# ── Cache ────────────────────────────────────────────────────────────────────
# Lock-protected because two scheduler ticks could race on the first load,
# and the read path is hot enough (every tick, every fleet/shard mail
# decky) that re-parsing on every call is wasteful.

_lock = threading.Lock()
_cache: list[EmailPersona] = []
_cache_path: Optional[Path] = None
_cache_mtime: float = 0.0


def load(*, language_default: str = "en") -> list[EmailPersona]:
    """Return the parsed global persona pool.

    *language_default* fills in any persona missing a ``language`` field;
    fleet/shard sources have no topology-level default, so callers
    should pass the worker's best guess (typically ``"en"``).

    Threadsafe and cheap on the steady state (mtime check + dict lookup);
    expensive only when the file changed since the last call.
    """
    path = resolve_path()
    try:
        st = path.stat()
    except OSError:
        with _lock:
            global _cache, _cache_path, _cache_mtime
            _cache = []
            _cache_path = path
            _cache_mtime = 0.0
        return []

    with _lock:
        if (
            _cache_path == path
            and _cache_mtime == st.st_mtime
            and _cache  # non-empty cache; empty re-parses cheaply anyway
        ):
            return _cache

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("realism global pool: read failed path=%s: %s", path, exc)
        return []

    # Re-stat after the read so the stored mtime reflects what we actually
    # parsed — a file change between the initial stat and read would otherwise
    # cache a stale mtime and suppress the next reload.
    try:
        st2 = path.stat()
    except OSError:
        st2 = st

    parsed = parse_personas(raw, language_default=language_default)
    with _lock:
        _cache = parsed
        _cache_path = path
        _cache_mtime = st2.st_mtime
    if parsed:
        logger.info(
            "realism global pool: loaded %d personas from %s", len(parsed), path,
        )
    return parsed


def reset_cache() -> None:
    """Clear the in-process cache.

    Test-only helper — avoids stale state when several tests in the
    same process exercise different on-disk pools.
    """
    global _cache, _cache_path, _cache_mtime
    with _lock:
        _cache = []
        _cache_path = None
        _cache_mtime = 0.0
