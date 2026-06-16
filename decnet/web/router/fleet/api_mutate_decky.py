# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST /deckies/{name}/mutate — operator-triggered single-decky mutate.

Returns 202 Accepted with one ``lifecycle_id`` per mutated decky.  The
real compose work runs in an ``asyncio.create_task``; the wizard polls
``GET /deckies/lifecycle?ids=...`` until terminal.

Auto-mutate (the watch-loop path) still goes through
``decnet.mutator.mutate_decky`` and is synchronous within that loop —
it's a background process, not an HTTP request, so it doesn't need
fire-and-forget.
"""
import asyncio
import os
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Path as PathParam, status

from decnet.bus.factory import get_bus
from decnet.config import DecnetConfig
from decnet.lifecycle.runner import run_mutate
from decnet.logging import get_logger
from decnet.mutator.engine import pick_new_services
from decnet.telemetry import traced as _traced
from decnet.web.db.models import LifecycleAcceptedResponse
from decnet.web.dependencies import require_admin, repo

log = get_logger("api.mutate")

router = APIRouter()


@router.post(
    "/deckies/{decky_name}/mutate",
    tags=["Fleet Management"],
    status_code=status.HTTP_202_ACCEPTED,
    response_model=LifecycleAcceptedResponse,
    responses={
        202: {"description": "Mutate accepted; poll GET /deckies/lifecycle?ids=..."},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "No active deployment, or decky not found, or no services available"},
        422: {"description": "Path parameter validation error (decky_name must match ^[a-z0-9\\-]{1,64}$)"},
    },
)
@_traced("api.mutate_decky")
async def api_mutate_decky(
    decky_name: str = PathParam(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> dict:
    if os.environ.get("DECNET_CONTRACT_TEST") == "true":
        return {"lifecycle_ids": ["contract-test"]}

    state_dict = await repo.get_state("deployment")
    if state_dict is None:
        raise HTTPException(status_code=404, detail="No active deployment")
    config = DecnetConfig(**state_dict["config"])
    compose_path = Path(state_dict["compose_path"])
    decky = next((d for d in config.deckies if d.name == decky_name), None)
    if decky is None:
        raise HTTPException(status_code=404, detail=f"Decky {decky_name} not found")

    new_services = pick_new_services(decky)
    if new_services is None:
        raise HTTPException(
            status_code=404,
            detail=f"No services available to mutate {decky_name}",
        )

    # Commit the new shape to the DB before spawning, so observers
    # don't see a half-applied mutation if the master crashes mid-task.
    decky.services = list(new_services)
    decky.last_mutated = time.time()
    await repo.set_state(
        "deployment",
        {"config": config.model_dump(), "compose_path": str(compose_path)},
    )

    lifecycle_id = await repo.create_lifecycle({
        "decky_name": decky.name,
        "host_uuid": decky.host_uuid,
        "operation": "mutate",
    })

    try:
        bus = get_bus(client_name="api.mutate")
    except Exception:
        bus = None

    asyncio.create_task(
        run_mutate(
            repo, bus,
            lifecycle_id=lifecycle_id,
            decky=decky,
            services=list(new_services),
            full_config=config,
            compose_path=compose_path,
        ),
        name=f"mutate-{decky.name}",
    )
    return {"lifecycle_ids": [lifecycle_id]}
