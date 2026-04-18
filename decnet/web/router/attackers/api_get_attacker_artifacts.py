from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo

router = APIRouter()


@router.get(
    "/attackers/{uuid}/artifacts",
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Attacker not found"},
    },
)
@_traced("api.get_attacker_artifacts")
async def get_attacker_artifacts(
    uuid: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """List captured file-drop artifacts for an attacker (newest first).

    Each entry is a `file_captured` log row — the frontend renders the
    badge/drawer using the same `fields` payload as /logs.
    """
    attacker = await repo.get_attacker_by_uuid(uuid)
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
    rows = await repo.get_attacker_artifacts(uuid)
    return {"total": len(rows), "data": rows}
