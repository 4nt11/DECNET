"""GET /api/v1/attackers/{uuid}/intel — latest threat-intel row for an attacker."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/attackers/{uuid}/intel",
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "No intel cached for this attacker"},
    },
)
@_traced("api.get_attacker_intel")
async def get_attacker_intel(
    uuid: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Return the most recent cached threat-intel verdict for an attacker.

    The row is populated out-of-band by the ``decnet enrich`` worker
    (typically within seconds of first observation, sub-second when the
    bus is healthy). 404 means either the worker has not run yet or the
    UUID does not correspond to an attacker DECNET has seen.
    """
    record = await repo.get_attacker_intel_by_uuid(uuid)
    if not record:
        raise HTTPException(
            status_code=404, detail="No intel cached for this attacker",
        )
    return record
