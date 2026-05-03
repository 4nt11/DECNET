"""
Artifact download endpoint.

SSH deckies farm attacker file drops into a host-mounted quarantine:
  /var/lib/decnet/artifacts/{decky}/ssh/{stored_as}

The capture event already flows through the normal log pipeline (one
RFC 5424 line per capture, see templates/ssh/emit_capture.py), so metadata
is served via /logs. This endpoint exists only to retrieve the raw bytes —
admin-gated because the payloads are attacker-controlled content.

Path resolution lives in :mod:`decnet.artifacts.paths` so the TTP
EmailLifter can share the exact same validation when it disk-reaches
``.eml`` files at tag-time (DEBT-047).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from decnet.artifacts.paths import ArtifactPathError, resolve_artifact_path
from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_admin

router = APIRouter()


@router.get(
    "/artifacts/{decky}/{stored_as}",
    tags=["Artifacts"],
    responses={
        400: {"description": "Invalid decky, service, or stored_as parameter"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required"},
        404: {"description": "Artifact not found"},
    },
)
@_traced("api.get_artifact")
async def get_artifact(
    decky: str,
    stored_as: str,
    service: str = Query("ssh", pattern=r"^[a-z]{1,16}$"),
    admin: dict = Depends(require_admin),
) -> FileResponse:
    try:
        path = resolve_artifact_path(decky, stored_as, service)
    except ArtifactPathError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not path.is_file():
        raise HTTPException(status_code=404, detail="artifact not found")
    return FileResponse(
        path=str(path),
        media_type="application/octet-stream",
        filename=stored_as,
        headers={
            "Content-Disposition": f'attachment; filename="{stored_as}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
