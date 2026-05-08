"""Shared asciinema shard helpers.

Extracted from ``decnet/web/router/transcripts/api_get_transcript.py``
so non-router callers (the BEHAVE-SHELL session-ended handler in
``decnet/profiler/worker.py``, the collector's session aggregator)
can resolve shard paths without crossing the layer boundary into the
FastAPI router.

Functions here speak in :class:`ValueError` — callers that want HTTP
semantics translate at the boundary. The router wrappers keep their
existing ``HTTPException`` behaviour for backwards compatibility.

PII boundary unchanged: shards live on disk; this module returns
:class:`pathlib.Path` pointers, never byte content. The ``_get_index``
cache stores byte offsets only.
"""
from __future__ import annotations

import os
import re
from collections import OrderedDict
from pathlib import Path

ARTIFACTS_ROOT = Path(
    os.environ.get("DECNET_ARTIFACTS_ROOT", "/var/lib/decnet/artifacts"),
)

_DECKY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SERVICE_RE = re.compile(r"^(ssh|telnet)$")
_SHARD_BASENAME_RE = re.compile(r"^sessions-\d{4}-\d{2}-\d{2}\.jsonl$")
_SID_LINE_RE = re.compile(rb'"sid"\s*:\s*"([a-f0-9-]{36})"')

# (path, mtime_ns) → {sid: [(offset, length), ...]}
_INDEX_CACHE: "OrderedDict[tuple[str, int], dict[str, list[tuple[int, int]]]]" = (
    OrderedDict()
)
_CACHE_MAX = 32


def validate_names(decky: str, service: str) -> None:
    """Raise :class:`ValueError` if ``decky`` / ``service`` look forged."""
    if not _DECKY_RE.fullmatch(decky):
        raise ValueError(f"invalid decky name: {decky!r}")
    if not _SERVICE_RE.fullmatch(service):
        raise ValueError(f"invalid service: {service!r}")


def resolve_shard(decky: str, service: str, shard_name: str) -> Path:
    """Resolve ``ARTIFACTS_ROOT/{decky}/{service}/transcripts/{shard_name}``
    with escape-attempt detection. Raises :class:`ValueError` on
    invalid inputs.
    """
    validate_names(decky, service)
    if not _SHARD_BASENAME_RE.fullmatch(shard_name):
        raise ValueError(f"invalid shard name: {shard_name!r}")
    root = ARTIFACTS_ROOT.resolve()
    candidate = (root / decky / service / "transcripts" / shard_name).resolve()
    if root not in candidate.parents and candidate != root:
        raise ValueError(f"path escapes artifacts root: {candidate}")
    return candidate


def _build_index(path: Path) -> dict[str, list[tuple[int, int]]]:
    index: dict[str, list[tuple[int, int]]] = {}
    with path.open("rb") as f:
        offset = 0
        for line in f:
            length = len(line)
            m = _SID_LINE_RE.search(line)
            if m:
                sid = m.group(1).decode("ascii")
                index.setdefault(sid, []).append((offset, length))
            offset += length
    return index


def get_index(path: Path) -> tuple[dict[str, list[tuple[int, int]]], int]:
    """Return ``(sid → [(offset, length), …], file_size)``.

    Cached by ``(path, mtime_ns)``; rebuilt when the shard changes.
    """
    st = path.stat()
    key = (str(path), st.st_mtime_ns)
    if key in _INDEX_CACHE:
        _INDEX_CACHE.move_to_end(key)
        return _INDEX_CACHE[key], st.st_size
    index = _build_index(path)
    _INDEX_CACHE[key] = index
    _INDEX_CACHE.move_to_end(key)
    while len(_INDEX_CACHE) > _CACHE_MAX:
        _INDEX_CACHE.popitem(last=False)
    return index, st.st_size


def find_shard_with_sid(decky: str, service: str, sid: str) -> Path | None:
    """Scan every ``sessions-YYYY-MM-DD.jsonl`` under the decky's
    transcripts dir until one claims this ``sid``.

    Newest shards first — most lookups are for recent sessions. Caches
    the per-shard sid index, so repeated calls are ~free until the
    shard's mtime changes.

    Returns ``None`` when nothing claims the sid OR when the
    transcripts dir is missing / unreadable. Never raises on
    filesystem-level errors — callers treat ``None`` as "skip".
    """
    validate_names(decky, service)
    root = ARTIFACTS_ROOT.resolve()
    transcripts_dir = (root / decky / service / "transcripts").resolve()
    if root not in transcripts_dir.parents:
        return None
    try:
        if not transcripts_dir.is_dir():
            return None
        entries = list(transcripts_dir.iterdir())
    except (OSError, PermissionError):
        return None
    shards = sorted(
        (p for p in entries if _SHARD_BASENAME_RE.fullmatch(p.name)),
        reverse=True,
    )
    for shard in shards:
        try:
            index, _size = get_index(shard)
        except (OSError, PermissionError):
            continue
        if sid in index:
            return shard
    return None
