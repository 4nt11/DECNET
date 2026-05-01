"""GET /api/v1/ttp/by-campaign/{campaign_uuid} — campaign-wide TTP rollup."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.db.models import CampaignTechniqueRow
from decnet.web.dependencies import require_viewer

router = APIRouter()


@router.get(
    "/ttp/by-campaign/{campaign_uuid}",
    tags=["TTP Tagging"],
    response_model=list[CampaignTechniqueRow],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Campaign not found"},
    },
)
@_traced("api.ttp.by_campaign")
async def api_ttp_by_campaign(
    campaign_uuid: str,
    user: dict[str, Any] = Depends(require_viewer),
) -> list[CampaignTechniqueRow]:
    """Campaign-rollup TTP rows. Empty at contract phase."""
    return []
