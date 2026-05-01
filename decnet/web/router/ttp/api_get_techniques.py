"""GET /api/v1/ttp/techniques — distinct techniques observed fleet-wide.

Returns an empty list at contract phase (E.1.9). Repo wiring lands in
E.1.10 / E.3 implementation; the response shape is stable from here.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.db.models import TechniqueRollupRow
from decnet.web.dependencies import require_viewer

router = APIRouter()


@router.get(
    "/ttp/techniques",
    tags=["TTP Tagging"],
    response_model=list[TechniqueRollupRow],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.ttp.list_techniques")
async def api_list_techniques(
    user: dict[str, Any] = Depends(require_viewer),
) -> list[TechniqueRollupRow]:
    """Distinct techniques observed across the fleet, with counts and
    last-seen timestamps. Empty list at contract phase."""
    return []
