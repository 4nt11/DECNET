"""GET /api/v1/ttp/by-attacker/{attacker_uuid} — per-IP TTP slice.

Backs the AttackerDetail page's TTP section. See TTP_TAGGING.md
§"UI surface" + project_attacker_detail_keep memory.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.db.models import IdentityTechniqueRow
from decnet.web.dependencies import require_viewer

router = APIRouter()


@router.get(
    "/ttp/by-attacker/{attacker_uuid}",
    tags=["TTP Tagging"],
    response_model=list[IdentityTechniqueRow],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Attacker not found"},
    },
)
@_traced("api.ttp.by_attacker")
async def api_ttp_by_attacker(
    attacker_uuid: str,
    user: dict[str, Any] = Depends(require_viewer),
) -> list[IdentityTechniqueRow]:
    """Per-Attacker (per-IP) TTP rows. Empty at contract phase."""
    return []
