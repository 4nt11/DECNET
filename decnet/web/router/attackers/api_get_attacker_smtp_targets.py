from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_viewer, repo

router = APIRouter()


@router.get(
    "/attackers/{uuid}/smtp-targets",
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Attacker not found"},
    },
)
@_traced("api.get_attacker_smtp_targets")
async def get_attacker_smtp_targets(
    uuid: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """List victim domains this attacker targeted via the SMTP honeypots.

    Rows are ordered by most-recent activity. Each row is one
    (attacker, domain) pair with a running count + first/last seen — no
    local-parts (user names) are ever stored, so this is safe to show
    to any viewer role.
    """
    attacker = await repo.get_attacker_by_uuid(uuid)
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
    rows = await repo.list_smtp_targets(uuid)
    return {"total": len(rows), "data": rows}
