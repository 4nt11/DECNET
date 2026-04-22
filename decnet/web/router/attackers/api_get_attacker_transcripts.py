from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo

router = APIRouter()


@router.get(
    "/attackers/{uuid}/transcripts",
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Attacker not found"},
    },
)
@_traced("api.get_attacker_transcripts")
async def get_attacker_transcripts(
    uuid: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """List PTY session recordings for an attacker (newest first).

    Each entry is a `session_recorded` log row — the frontend lists them
    in the AttackerDetail Sessions tab and opens SessionDrawer on click.
    """
    attacker = await repo.get_attacker_by_uuid(uuid)
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
    rows = await repo.get_attacker_transcripts(uuid)
    return {"total": len(rows), "data": rows}
