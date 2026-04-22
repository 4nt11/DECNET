"""
Paged asciinema v2 transcript endpoint.

Transcripts are stored as one JSONL day-shard per (decky, UTC day) under
    /var/lib/decnet/artifacts/{decky}/{service}/transcripts/sessions-YYYY-MM-DD.jsonl
Each line carries a ``sid`` tag; multiple concurrent sessions interleave into
the same shard (O_APPEND + sub-PIPE_BUF writes keep lines atomic — see
decnet/templates/_shared/sessrec/sessrec.c for the guarantee).

Rather than scanning the whole shard on every request, the first hit for a
given (shard path, mtime) builds an in-memory index of ``sid → [byte offsets]``
by one pass. Subsequent paged reads pread() exact line slices in O(limit).
Index is bounded by the disk-free precheck (< 200 MB free → no recording)
and the 10 MB per-session cap.
"""

from __future__ import annotations

import json
import os
import re
from collections import OrderedDict
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_admin, repo

router = APIRouter()

ARTIFACTS_ROOT = Path(os.environ.get("DECNET_ARTIFACTS_ROOT", "/var/lib/decnet/artifacts"))

_DECKY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SID_RE = re.compile(r"^[a-f0-9-]{36}$")
_SERVICE_RE = re.compile(r"^(ssh|telnet)$")
# Shard filename is built by sessrec from UTC date — keep the charset tight
# so a forged shard_path in the Log row can't traverse.
_SHARD_BASENAME_RE = re.compile(r"^sessions-\d{4}-\d{2}-\d{2}\.jsonl$")

# (path, mtime_ns) → {sid: [(offset, length), ...]}
_INDEX_CACHE: "OrderedDict[tuple[str, int], dict[str, list[tuple[int, int]]]]" = OrderedDict()
_CACHE_MAX = 32


def _get_index(path: Path) -> tuple[dict[str, list[tuple[int, int]]], int]:
    st = path.stat()
    key = (str(path), st.st_mtime_ns)
    if key in _INDEX_CACHE:
        _INDEX_CACHE.move_to_end(key)
        return _INDEX_CACHE[key], st.st_size
    index: dict[str, list[tuple[int, int]]] = {}
    with path.open("rb") as f:
        offset = 0
        for line in f:
            length = len(line)
            # Fast sid extract: look for `"sid":"<36 chars>"` prefix — every
            # sessrec line starts with that field (see emit_*).
            try:
                m = re.search(rb'"sid"\s*:\s*"([a-f0-9-]{36})"', line)
            except re.error:
                m = None
            if m:
                sid = m.group(1).decode("ascii")
                index.setdefault(sid, []).append((offset, length))
            offset += length
    _INDEX_CACHE[key] = index
    _INDEX_CACHE.move_to_end(key)
    while len(_INDEX_CACHE) > _CACHE_MAX:
        _INDEX_CACHE.popitem(last=False)
    return index, st.st_size


def _resolve_shard(decky: str, service: str, shard_name: str) -> Path:
    if not _DECKY_RE.fullmatch(decky):
        raise HTTPException(status_code=400, detail="invalid decky name")
    if not _SERVICE_RE.fullmatch(service):
        raise HTTPException(status_code=400, detail="invalid service")
    if not _SHARD_BASENAME_RE.fullmatch(shard_name):
        raise HTTPException(status_code=400, detail="invalid shard name")
    root = ARTIFACTS_ROOT.resolve()
    candidate = (root / decky / service / "transcripts" / shard_name).resolve()
    if root not in candidate.parents and candidate != root:
        raise HTTPException(status_code=400, detail="path escapes artifacts root")
    return candidate


@router.get(
    "/transcripts/{decky}/{sid}",
    tags=["Transcripts"],
    responses={
        400: {"description": "Invalid decky or sid parameter"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required"},
        404: {"description": "Transcript not found"},
    },
)
@_traced("api.get_transcript")
async def get_transcript(
    decky: str,
    sid: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=5000),
    admin: dict = Depends(require_admin),
) -> dict[str, Any]:
    if not _DECKY_RE.fullmatch(decky):
        raise HTTPException(status_code=400, detail="invalid decky name")
    if not _SID_RE.fullmatch(sid):
        raise HTTPException(status_code=400, detail="invalid sid")

    log = await repo.get_session_log(sid)
    if not log:
        raise HTTPException(status_code=404, detail="session not found")

    try:
        fields = json.loads(log.get("fields") or "{}")
    except (ValueError, TypeError):
        fields = {}

    service = fields.get("service") or log.get("service")
    shard_path_field = fields.get("shard_path") or ""
    shard_name = Path(shard_path_field).name
    log_decky = log.get("decky") or fields.get("decky")

    if log_decky and log_decky != decky:
        raise HTTPException(status_code=404, detail="session not found")

    path = _resolve_shard(decky, service or "", shard_name or "")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="transcript not found")

    index, _size = _get_index(path)
    lines_meta = index.get(sid)
    if not lines_meta:
        raise HTTPException(status_code=404, detail="sid not present in shard")

    header: dict[str, Any] = {}
    events: list[list[Any]] = []
    truncated = False

    # First pass: find the header line (has "hdr" key) and count events.
    # Keep it O(n lines for this sid), not O(shard).
    total_events = 0
    event_positions: list[tuple[int, int]] = []
    with path.open("rb") as f:
        for off, ln in lines_meta:
            f.seek(off)
            raw = f.read(ln)
            try:
                obj = json.loads(raw)
            except ValueError:
                continue
            if "hdr" in obj:
                header = obj["hdr"]
                continue
            if obj.get("trunc"):
                truncated = True
                continue
            event_positions.append((off, ln))
            total_events += 1

        # Page the events window.
        window = event_positions[offset:offset + limit]
        for off, ln in window:
            f.seek(off)
            raw = f.read(ln)
            try:
                obj = json.loads(raw)
            except ValueError:
                continue
            t = obj.get("t")
            ch = obj.get("ch")
            d = obj.get("d")
            if t is None or ch is None or d is None:
                continue
            events.append([t, ch, d])

    return {
        "sid": sid,
        "service": service,
        "header": header,
        "events": events,
        "offset": offset,
        "limit": limit,
        "total": total_events,
        "has_more": (offset + limit) < total_events,
        "truncated": truncated,
    }
