"""GET ``/api/v1/realism/synthetic-files`` — browse planted realism files.

The orchestrator's realism worker grows synthetic files on each decky
(notes, TODOs, drafts, scripts, log lines, canary artifacts). The
:class:`~decnet.web.db.models.realism.SyntheticFile` table is the
canonical record of what's been planted where; this endpoint lets
operators inspect the lineage without ssh'ing into a decky.

Read-only. No writes — the orchestrator is the sole writer; the
dashboard is observation surface only.

The body preview (``last_body``) is repo-clipped at 64 KB
(:data:`SYNTHETIC_FILE_BODY_LIMIT`); when the original was larger the
detail response carries ``truncated: true`` so the operator knows what
they're looking at.
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from decnet.telemetry import traced as _traced
from decnet.web.db.models.realism import SYNTHETIC_FILE_BODY_LIMIT
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/realism/synthetic-files",
    tags=["Realism"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error"},
    },
)
@_traced("api.realism.list_synthetic_files")
async def list_synthetic_files(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=2147483647),
    decky_uuid: Optional[str] = Query(None, max_length=64),
    persona: Optional[str] = Query(None, max_length=128),
    content_class: Optional[str] = Query(None, max_length=32),
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Paginated synthetic_files newest-first.

    Filters: ``decky_uuid``, ``persona``, ``content_class``. The list
    response strips ``last_body`` to keep the payload bounded — fetch
    the detail endpoint for the body preview.
    """
    rows = await repo.list_synthetic_files(
        decky_uuid=decky_uuid,
        persona=persona,
        content_class=content_class,
        limit=limit,
        offset=offset,
    )
    total = await repo.count_synthetic_files(
        decky_uuid=decky_uuid,
        persona=persona,
        content_class=content_class,
    )
    # The list view doesn't need bodies; drop them so the response stays
    # small even when 50 rows each carry ~64 KB. Detail endpoint returns
    # the body.
    for r in rows:
        r.pop("last_body", None)
    return {"total": total, "limit": limit, "offset": offset, "data": rows}


@router.get(
    "/realism/synthetic-files/{uuid}",
    tags=["Realism"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Synthetic file not found"},
    },
)
@_traced("api.realism.get_synthetic_file")
async def get_synthetic_file(
    uuid: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Return one synthetic_files row including the body preview.

    ``truncated`` is true when the stored body is at the cap — the
    decky filesystem holds the canonical bytes; the master view is a
    snapshot.
    """
    row = await repo.get_synthetic_file(uuid)
    if row is None:
        raise HTTPException(status_code=404, detail="synthetic file not found")
    body = row.get("last_body") or ""
    row["truncated"] = len(body) >= SYNTHETIC_FILE_BODY_LIMIT
    return row
