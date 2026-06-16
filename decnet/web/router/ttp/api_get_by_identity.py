# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/ttp/by-identity/{identity_uuid} — Identity-scoped TTP rollup.

Primary endpoint for the IdentityDetail "TTPs Observed" section. See
TTP_TAGGING.md §"UI surface". Empty at contract phase (E.1.9).
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.db.models import IdentityTechniqueRow
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/ttp/by-identity/{identity_uuid}",
    tags=["TTP Tagging"],
    response_model=list[IdentityTechniqueRow],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Identity not found"},
    },
)
@_traced("api.ttp.by_identity")
async def api_ttp_by_identity(
    identity_uuid: str,
    user: dict[str, Any] = Depends(require_viewer),
) -> list[IdentityTechniqueRow]:
    """Per-Identity TTP heatmap rows."""
    return await repo.list_techniques_by_identity(identity_uuid)
