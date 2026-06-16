# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/identities/{uuid} — single identity row.

Soft-merge handling: if the requested UUID has merged_into_uuid set,
the repository follows the chain and returns the winner. Callers always
receive the canonical identity for any UUID that has ever been part of
the merge tree.

Returns 404 against an empty/unknown UUID — expected response while the
clusterer hasn't run yet.
"""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/identities/{uuid}",
    tags=["Identity Resolution"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Identity not found"},
    },
)
@_traced("api.get_identity_detail")
async def get_identity_detail(
    uuid: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    identity = await repo.get_identity_by_uuid(uuid)
    if not identity:
        raise HTTPException(status_code=404, detail="Identity not found")
    # Cheap aggregates the IdentityDetail page surfaces. Counted off the
    # FK rather than maintained in observation_count so the answer is
    # always live (the denormalized field can lag the clusterer briefly).
    identity["observation_count_live"] = await repo.count_observations_for_identity(
        identity["uuid"]
    )
    return identity
