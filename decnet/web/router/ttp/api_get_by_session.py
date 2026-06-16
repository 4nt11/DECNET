# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/ttp/by-session/{session_id} — session timeline of TTP tags."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.db.models import IdentityTechniqueRow
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/ttp/by-session/{session_id}",
    tags=["TTP Tagging"],
    response_model=list[IdentityTechniqueRow],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Session not found"},
    },
)
@_traced("api.ttp.by_session")
async def api_ttp_by_session(
    session_id: str,
    user: dict[str, Any] = Depends(require_viewer),
) -> list[IdentityTechniqueRow]:
    """Per-session TTP tag timeline."""
    return await repo.list_techniques_by_session(session_id)
