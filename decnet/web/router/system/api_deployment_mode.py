# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /system/deployment-mode — tells the UI whether a deploy will shard
across SWARM workers or land on the master itself.

Logic mirrors the auto-mode branch in ``api_deploy_deckies``: master role
plus at least one reachable enrolled worker = swarm; otherwise unihost.
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_viewer

router = APIRouter()


class DeploymentModeResponse(BaseModel):
    mode: str  # "swarm" or "unihost"
    role: str  # "master" or "agent"
    swarm_host_count: int


# Auth-gated (V4.1.6): the response leaks host role + enrolled-worker count,
# which is recon-useful to an unauthenticated attacker. The dashboard only ever
# calls this from inside the post-login app shell (App.tsx gates the whole app
# behind a valid token), so there is no pre-auth UI-mode use case to preserve —
# gate the entire endpoint behind require_viewer rather than splitting it.
@router.get("/deployment-mode", response_model=DeploymentModeResponse)
async def get_deployment_mode(
    repo: BaseRepository = Depends(get_repo),
    _user: dict = Depends(require_viewer),
) -> DeploymentModeResponse:
    role = os.environ.get("DECNET_MODE", "master").lower()
    hosts = 0
    if role == "master":
        hosts = sum(
            1 for h in await repo.list_swarm_hosts()
            if h.get("status") in ("active", "enrolled") and h.get("address")
        )
    return DeploymentModeResponse(
        mode="swarm" if hosts > 0 else "unihost",
        role=role,
        swarm_host_count=hosts,
    )
