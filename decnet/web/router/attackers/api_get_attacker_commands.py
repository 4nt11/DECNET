from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from decnet.web.dependencies import get_current_user, repo

router = APIRouter()


@router.get(
    "/attackers/{uuid}/commands",
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        404: {"description": "Attacker not found"},
    },
)
async def get_attacker_commands(
    uuid: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=2147483647),
    service: Optional[str] = None,
    current_user: str = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve paginated commands for an attacker profile."""
    attacker = await repo.get_attacker_by_uuid(uuid)
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")

    def _norm(v: Optional[str]) -> Optional[str]:
        if v in (None, "null", "NULL", "undefined", ""):
            return None
        return v

    result = await repo.get_attacker_commands(
        uuid=uuid, limit=limit, offset=offset, service=_norm(service),
    )
    return {"total": result["total"], "limit": limit, "offset": offset, "data": result["data"]}
