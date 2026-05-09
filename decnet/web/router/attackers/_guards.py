"""Shared helpers for the per-attacker routes.

Currently houses the 404 guard used by the SSE events stream
(:mod:`api_events`). Mirrors the topology router's
``_guards.get_topology_or_404`` shape so a future grep for "guard"
finds both.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from decnet.web.dependencies import repo


async def get_attacker_or_404(attacker_uuid: str) -> dict[str, Any]:
    """Fetch an Attacker row by UUID or raise 404.

    The 404 fires *after* auth (the route's role gate runs first), so
    an existence probe can't leak a UUID's presence to an
    unauthenticated caller.
    """
    attacker = await repo.get_attacker_by_uuid(attacker_uuid)
    if not attacker:
        raise HTTPException(status_code=404, detail="Attacker not found")
    return attacker
