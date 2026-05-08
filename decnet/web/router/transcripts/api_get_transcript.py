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
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from decnet.artifacts.shards import (
    ARTIFACTS_ROOT as ARTIFACTS_ROOT,  # re-export for monkeypatching tests
    _SHARD_BASENAME_RE,
    find_shard_with_sid as _shared_find_shard_with_sid,
    get_index as _get_index,
    resolve_shard as _shared_resolve_shard,
    validate_names as _shared_validate_names,
)
from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_admin, repo

router = APIRouter()

_DECKY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SID_RE = re.compile(r"^[a-f0-9-]{36}$")


def _validate_names(decky: str, service: str) -> None:
    """Router-level wrapper: translate ValueError → HTTPException(400)."""
    try:
        _shared_validate_names(decky, service)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _resolve_shard(decky: str, service: str, shard_name: str) -> Path:
    try:
        return _shared_resolve_shard(decky, service, shard_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _find_shard_with_sid(decky: str, service: str, sid: str) -> Path | None:
    """Router-level wrapper around the shared helper.

    Translates the ValueError on bad names into HTTPException(400) so
    the route handler's existing error UX is preserved.
    """
    try:
        return _shared_find_shard_with_sid(decky, service, sid)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


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
    offset: int = Query(0, ge=0, le=2147483647),
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

    # Fast path: the Log row carries a fields.shard_path we can validate
    # and hit directly. Falls back to scanning all shards when the SD
    # didn't include one (current sessrec.c doesn't emit shard_path) or
    # when the named shard isn't on disk anymore.
    path: Path | None = None
    if _SHARD_BASENAME_RE.fullmatch(shard_name or ""):
        candidate = _resolve_shard(decky, service or "", shard_name)
        if candidate.is_file():
            path = candidate
    if path is None:
        path = _find_shard_with_sid(decky, service or "", sid)
    if path is None:
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
