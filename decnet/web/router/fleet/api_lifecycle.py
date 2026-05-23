# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /deckies/lifecycle?ids=… — poll lifecycle rows by id.

The wizard polls this endpoint every ~2 s after POSTing /deckies/deploy
or /deckies/{name}/mutate (which return 202 with the lifecycle ids) and
stops when every row reaches a terminal status.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.web.db.models import DeckyLifecycleListResponse, DeckyLifecycleView
from decnet.web.dependencies import require_viewer, repo

log = get_logger("api.lifecycle")

router = APIRouter()


@router.get(
    "/deckies/lifecycle",
    tags=["Fleet Management"],
    response_model=DeckyLifecycleListResponse,
    responses={
        401: {"description": "Could not validate credentials"},
        422: {"description": "Validation error (ids missing or malformed)"},
    },
)
@_traced("api.lifecycle_get")
async def api_get_lifecycle(
    ids: list[str] = Query(
        ..., description="One or more DeckyLifecycle row ids; pass repeated ?ids=<uuid>&ids=<uuid> in the URL.",
        min_length=1, max_length=200,
    ),
    user: dict = Depends(require_viewer),
) -> dict:
    rows = await repo.get_lifecycle_by_ids(ids)
    return {
        "rows": [DeckyLifecycleView(**r).model_dump() for r in rows],
    }
