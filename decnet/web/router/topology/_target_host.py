"""Shared validation for the ``mode`` / ``target_host_uuid`` pair.

Called by the two topology-create endpoints
(``api_create_topology``, ``api_create_blank_topology``).  Kept as a
tiny module so the rules stay in one place when Step 6 grows the list
(e.g. when we start rejecting hosts that already own a topology).
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import HTTPException

# Hosts we're willing to route a new topology to.  ``enrolled`` is fine
# because the agent process has certs and will answer mTLS calls as
# soon as it's up; ``active`` means we've seen a heartbeat recently.
_ROUTABLE_HOST_STATUSES = {"enrolled", "active"}


async def validate_target_host(
    repo: Any,
    mode: str,
    target_host_uuid: Optional[str],
) -> None:
    """Raise HTTPException(400) if the mode/host combination is invalid.

    Rules:
      - ``mode=="unihost"`` with a ``target_host_uuid`` → 400 (nonsense).
      - ``mode=="agent"`` without ``target_host_uuid`` → 400.
      - ``mode=="agent"`` with an unknown uuid → 400.
      - ``mode=="agent"`` pointing at a host in ``unreachable`` /
        ``decommissioned`` → 400 (operator asked for a broken path).
    """
    if mode == "unihost":
        if target_host_uuid is not None:
            raise HTTPException(
                status_code=400,
                detail="target_host_uuid is only valid when mode='agent'",
            )
        return

    if mode == "agent":
        if not target_host_uuid:
            raise HTTPException(
                status_code=400,
                detail="mode='agent' requires target_host_uuid",
            )
        host = await repo.get_swarm_host_by_uuid(target_host_uuid)
        if host is None:
            raise HTTPException(
                status_code=400,
                detail=f"unknown swarm host {target_host_uuid!r}",
            )
        if host.get("status") not in _ROUTABLE_HOST_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"swarm host {target_host_uuid!r} is "
                    f"{host.get('status')!r}; expected one of "
                    f"{sorted(_ROUTABLE_HOST_STATUSES)}"
                ),
            )
        return

    # Shouldn't happen — the pydantic pattern should have rejected it.
    raise HTTPException(status_code=400, detail=f"unknown mode {mode!r}")
