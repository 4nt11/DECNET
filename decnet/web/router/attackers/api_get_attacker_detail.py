from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.web.dependencies import require_viewer, repo

router = APIRouter()


@router.get(
    "/attackers/{uuid}",
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        404: {"description": "Attacker not found"},
    },
)
async def get_attacker_detail(
    uuid: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Retrieve a single attacker profile by UUID (with behavior block)."""
    attacker = await repo.get_attacker_by_uuid(uuid)
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
    attacker["behavior"] = await repo.get_attacker_behavior(uuid)
    return attacker
