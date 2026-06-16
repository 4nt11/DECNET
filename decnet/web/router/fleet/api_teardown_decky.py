# SPDX-License-Identifier: AGPL-3.0-or-later
"""DELETE /deckies/{name} — operator-triggered single-decky teardown.

Exposes the engine's per-decky teardown (previously CLI-only via
``decnet teardown --id <name>``). Synchronous: the compose stop/rm of one
decky's services is quick, so we await it off-thread and return 204 rather
than the 202+lifecycle dance that deploy/mutate use for slow image builds.

The single-decky teardown path does NOT touch the host macvlan interface
(that's only the teardown-all branch), so it needs no CAP_NET_ADMIN beyond
what the web service already holds.

State consistency is the subtle part. ``engine.teardown`` removes the
containers and the decky's ``fleet_deckies`` row, but it does NOT prune the
decky from ``decnet-state.json``. If we left it there, the reconciler would
see "present in JSON, absent from DB" and re-INSERT the row — resurrecting
the decky in the UI. So we prune it from both decnet-state.json (load/save)
and the DB ``deployment`` key (the mutate plane's store) after teardown.
"""
import asyncio
import os

import anyio
from fastapi import APIRouter, Depends, HTTPException, Path as PathParam, Response, status

from decnet.config import clear_state, load_state, save_state
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.web.db.models import LOCAL_HOST_SENTINEL
from decnet.web.dependencies import require_admin, repo

log = get_logger("api.teardown")

router = APIRouter()


@router.delete(
    "/deckies/{decky_name}",
    tags=["Fleet Management"],
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        204: {"description": "Decky torn down and removed from the fleet"},
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "No active deployment, or decky not found"},
        422: {"description": "Path parameter validation error (decky_name must match ^[a-z0-9\\-]{1,64}$)"},
    },
)
@_traced("api.teardown_decky")
async def api_teardown_decky(
    decky_name: str = PathParam(..., pattern=r"^[a-z0-9\-]{1,64}$"),
    admin: dict = Depends(require_admin),
) -> Response:
    loaded = await asyncio.to_thread(load_state)
    if loaded is None:
        raise HTTPException(status_code=404, detail="No active deployment")
    config, compose_path = loaded
    decky = next((d for d in config.deckies if d.name == decky_name), None)
    if decky is None:
        raise HTTPException(status_code=404, detail=f"Decky {decky_name} not found")

    if os.environ.get("DECNET_CONTRACT_TEST") != "true":
        # Stops/removes the decky's containers, emits a retirement lifecycle
        # event, and drops its fleet_deckies row. Sync engine call, off-thread
        # so it doesn't block the event loop.
        from decnet.engine import teardown as engine_teardown
        await anyio.to_thread.run_sync(engine_teardown, decky_name)
    else:
        # Engine teardown is skipped under contract tests (no docker); still
        # drop the fleet_deckies row so the inventory reflects the deletion.
        await repo.delete_fleet_decky(
            host_uuid=decky.host_uuid or LOCAL_HOST_SENTINEL, name=decky_name,
        )

    # Prune the decky from persisted state so the reconciler doesn't resurrect
    # it (JSON-has / DB-doesn't -> reconciler re-INSERTs the fleet_deckies row).
    # DecnetConfig.deckies has min_length=1, so an empty fleet clears state
    # entirely rather than persisting an invalid config.
    remaining = [d for d in config.deckies if d.name != decky_name]
    if remaining:
        config.deckies = remaining
        await asyncio.to_thread(save_state, config, compose_path)
        await repo.set_state(
            "deployment",
            {"config": config.model_dump(), "compose_path": str(compose_path)},
        )
    else:
        await asyncio.to_thread(clear_state)
        await repo.set_state("deployment", None)

    log.info("decky torn down via API decky=%s remaining=%d", decky_name, len(remaining))
    return Response(status_code=status.HTTP_204_NO_CONTENT)
