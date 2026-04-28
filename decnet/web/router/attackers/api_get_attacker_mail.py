from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import require_admin, repo

router = APIRouter()


@router.get(
    "/attackers/{uuid}/mail",
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Admin access required"},
        404: {"description": "Attacker not found"},
    },
)
@_traced("api.get_attacker_mail")
async def get_attacker_mail(
    uuid: str,
    admin: dict = Depends(require_admin),
) -> dict[str, Any]:
    """List stored messages this attacker relayed via the SMTP honeypots.

    Each entry is a ``message_stored`` log row — headers + attachment
    manifest live in ``fields``; the raw .eml bytes are fetched via
    ``/artifacts/{decky}/{stored_as}?service=smtp`` (also admin-gated).
    Admin-only because message bodies are attacker-controlled content
    and may include phishing kits / malware droppers.
    """
    attacker = await repo.get_attacker_by_uuid(uuid)
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
    rows = await repo.get_attacker_stored_mail(uuid)
    return {"total": len(rows), "data": rows}
