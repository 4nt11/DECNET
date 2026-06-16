# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /swarm/health — controller liveness (no I/O)."""
from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/health", tags=["Swarm Health"])
async def api_get_swarm_health() -> dict[str, str]:
    return {"status": "ok", "role": "swarm-controller"}
