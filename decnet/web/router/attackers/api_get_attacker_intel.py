"""GET /api/v1/attackers/{ip}/intel — latest threat-intel row for an IP."""
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_viewer

router = APIRouter()


@router.get(
    "/attackers/{ip}/intel",
    tags=["Attacker Profiles"],
    responses={
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "No intel cached for this IP"},
    },
)
@_traced("api.get_attacker_intel")
async def get_attacker_intel(
    ip: str,
    user: dict = Depends(require_viewer),
) -> dict[str, Any]:
    """Return the most recent cached threat-intel verdict for ``ip``.

    The row is populated out-of-band by the ``decnet enrich`` worker
    (typically within seconds of first observation, sub-second when the
    bus is healthy). 404 means either the worker has not run yet or the
    IP has never been observed by DECNET.
    """
    record = await repo.get_attacker_intel_by_ip(ip)
    if not record:
        raise HTTPException(status_code=404, detail="No intel cached for this IP")
    return record
