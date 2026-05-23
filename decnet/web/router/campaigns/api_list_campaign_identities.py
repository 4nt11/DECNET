# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/campaigns/{uuid}/identities — identities for a campaign.

Returns the ``AttackerIdentity`` rows whose ``campaign_id`` FK points
at this campaign. Mirror of
:mod:`decnet.web.router.identities.api_list_identity_observations`.
"""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/campaigns/{uuid}/identities",
    tags=["Campaign Clustering"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Campaign not found"},
    },
)
@_traced("api.list_campaign_identities")
async def list_campaign_identities(
    uuid: str,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    campaign = await repo.get_campaign_by_uuid(uuid)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    canonical_uuid = campaign["uuid"]
    data = await repo.list_identities_for_campaign(
        canonical_uuid, limit=limit, offset=offset
    )
    total = await repo.count_identities_for_campaign(canonical_uuid)
    return {"total": total, "limit": limit, "offset": offset, "data": data}
