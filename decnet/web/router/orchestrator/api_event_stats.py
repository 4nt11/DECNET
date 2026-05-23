# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/orchestrator/events/stats — authoritative failure count.

The dashboard's failure-count badge previously derived its number from
the in-memory SSE buffer + a single paginated page (capped at 500 +
limit rows). On busy fleets, failures older than the local window
were silently excluded and the badge read low — see DEBT-042. This
endpoint returns the real count straight from the DB so the badge
matches reality.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()

_SINCE_RE = re.compile(r"^(\d+)([smhd])$")
# Bounded to avoid unintentionally-expensive scans. 7d covers the
# operator UX use case (failure-count badge) while still returning
# in O(index seek + count).
_MAX_SINCE = timedelta(days=7)


def _parse_since(s: str) -> timedelta:
    m = _SINCE_RE.match(s)
    if not m:
        raise HTTPException(
            status_code=422,
            detail="since must match ^(\\d+)[smhd]$ (e.g. '15m', '1h', '24h', '7d')",
        )
    value, unit = int(m.group(1)), m.group(2)
    if value <= 0:
        raise HTTPException(status_code=422, detail="since must be > 0")
    delta = {
        "s": timedelta(seconds=value),
        "m": timedelta(minutes=value),
        "h": timedelta(hours=value),
        "d": timedelta(days=value),
    }[unit]
    if delta > _MAX_SINCE:
        raise HTTPException(
            status_code=422,
            detail=f"since exceeds maximum window of {_MAX_SINCE}",
        )
    return delta


@router.get(
    "/orchestrator/events/stats",
    tags=["Orchestrator"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.orchestrator.events.stats")
async def orchestrator_event_stats(
    since: str = Query("1h", description="Window relative to now, e.g. '15m', '1h', '24h'."),
    success: Optional[bool] = Query(
        None,
        description="If set, restrict the count to rows with this success value.",
    ),
    kind: Optional[str] = Query(
        None, pattern="^(traffic|file|email)$",
    ),
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Aggregate counts for the orchestrator activity feed.

    Today only the failure-count badge consumes this surface, so the
    only supported aggregate is ``success=false`` (everything else is
    rejected — ``success=true`` and the unfiltered total can be served
    by the existing ``count`` on the list endpoint without a window
    filter, and we'd rather not paint ourselves into a corner before
    the next consumer shows up).
    """
    if success is not False:
        raise HTTPException(
            status_code=422,
            detail="only success=false is supported on this surface today",
        )
    delta = _parse_since(since)
    since_ts = datetime.now(timezone.utc) - delta
    count = await repo.count_orchestrator_failures(
        since_ts=since_ts, kind=kind,
    )
    return {
        "since": since,
        "success": success,
        "kind": kind,
        "count": count,
    }
