# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/identities/{uuid}/observations — observations for an identity.

Returns the per-IP ``Attacker`` rows whose ``identity_id`` FK points at
this identity. The shape mirrors ``AttackersResponse`` so the frontend
can reuse the same row component as the main attackers list.

Empty result while the clusterer hasn't linked any observations yet.
"""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/identities/{uuid}/observations",
    tags=["Identity Resolution"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Identity not found"},
    },
)
@_traced("api.list_identity_observations")
async def list_identity_observations(
    uuid: str,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0, le=2147483647),
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    # 404 if the identity itself doesn't exist. Otherwise return the
    # observations linked to it (which may be empty — a freshly-formed
    # identity briefly has no observations yet from the FK side).
    identity = await repo.get_identity_by_uuid(uuid)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    # If the requested uuid was merged, return observations under the
    # winner's uuid (which is what get_identity_by_uuid resolves to).
    canonical_uuid = identity["uuid"]
    data = await repo.list_observations_for_identity(
        canonical_uuid, limit=limit, offset=offset
    )
    total = await repo.count_observations_for_identity(canonical_uuid)
    return {"total": total, "limit": limit, "offset": offset, "data": data}
