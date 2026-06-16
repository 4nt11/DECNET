# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/campaigns/{uuid} — single campaign row.

Soft-merge handling: if the requested UUID has merged_into_uuid set,
the repository follows the chain and returns the winner. Mirror of
:mod:`decnet.web.router.identities.api_get_identity_detail`.
"""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/campaigns/{uuid}",
    tags=["Campaign Clustering"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Campaign not found"},
    },
)
@_traced("api.get_campaign_detail")
async def get_campaign_detail(
    uuid: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    campaign = await repo.get_campaign_by_uuid(uuid)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    # Cheap aggregate the CampaignDetail page surfaces — counted off
    # the FK rather than the denormalized identity_count so the answer
    # is always live.
    campaign["identity_count_live"] = await repo.count_identities_for_campaign(
        campaign["uuid"]
    )
    return campaign
