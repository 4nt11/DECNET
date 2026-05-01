"""GET /api/v1/ttp/export/navigator{,/identity/{uuid}} — Navigator JSON layer.

Empty-but-valid Navigator layer at contract phase per TTP_TAGGING.md
§"UI surface — Empty state": a SOC analyst pasting the JSON into the
official MITRE ATT&CK Navigator sees the file load with no
highlighted techniques — correct, not broken.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from decnet.telemetry import traced as _traced
from decnet.web.db.models import NavigatorLayer
from decnet.web.dependencies import require_viewer

router = APIRouter()


@router.get(
    "/ttp/export/navigator",
    tags=["TTP Tagging"],
    response_model=NavigatorLayer,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
    },
)
@_traced("api.ttp.export_navigator_fleet")
async def api_export_navigator_fleet(
    user: dict[str, Any] = Depends(require_viewer),
) -> NavigatorLayer:
    """Fleet-wide Navigator layer. Empty-but-valid at contract phase."""
    return NavigatorLayer(name="DECNET TTP coverage — fleet")


@router.get(
    "/ttp/export/navigator/identity/{identity_uuid}",
    tags=["TTP Tagging"],
    response_model=NavigatorLayer,
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Identity not found"},
    },
)
@_traced("api.ttp.export_navigator_identity")
async def api_export_navigator_identity(
    identity_uuid: str,
    user: dict[str, Any] = Depends(require_viewer),
) -> NavigatorLayer:
    """Per-Identity Navigator layer (the SOC demo)."""
    return NavigatorLayer(
        name=f"DECNET TTP coverage — identity {identity_uuid}",
    )
