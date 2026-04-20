"""POST /swarm/hosts/{uuid}/teardown — remote teardown on a swarm worker.

Body: ``{"decky_id": "..."}`` (optional). When ``decky_id`` is null/omitted
the agent tears down the entire host (all deckies + network); otherwise it
tears down that single decky.

Async-by-default: the endpoint returns 202 the moment the request is
accepted and runs the actual agent call + DB cleanup in a background task.
That lets the operator queue multiple teardowns in parallel without
blocking on slow docker-compose-down cycles on the worker.
"""
from __future__ import annotations

import asyncio
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from decnet.logging import get_logger
from decnet.swarm.client import AgentClient
from decnet.web.db.repository import BaseRepository
from decnet.web.dependencies import get_repo, require_admin

log = get_logger("swarm.teardown")
router = APIRouter()

# Track spawned background tasks so (a) they're not GC'd mid-flight and
# (b) tests can drain them deterministically via ``await drain_pending()``.
_PENDING: "set[asyncio.Task]" = set()


def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _PENDING.add(task)
    task.add_done_callback(_PENDING.discard)
    return task


async def drain_pending() -> None:
    """Await all outstanding teardown tasks. Used by tests."""
    while _PENDING:
        await asyncio.gather(*list(_PENDING), return_exceptions=True)


class TeardownHostRequest(BaseModel):
    decky_id: Optional[str] = None


class TeardownHostResponse(BaseModel):
    host_uuid: str
    host_name: str
    decky_id: Optional[str] = None
    accepted: bool
    detail: str


async def _mark_tearing_down(
    repo: BaseRepository, host_uuid: str, decky_id: Optional[str]
) -> None:
    """Flip affected shards to state='tearing_down' so the UI can show
    progress immediately while the background task runs."""
    shards = await repo.list_decky_shards(host_uuid)
    for s in shards:
        if decky_id and s.get("decky_name") != decky_id:
            continue
        await repo.upsert_decky_shard({
            **s,
            "state": "tearing_down",
            "last_error": None,
        })


async def _run_teardown(
    host: dict[str, Any], repo: BaseRepository, decky_id: Optional[str]
) -> None:
    """Fire the remote teardown + DB cleanup. Exceptions are logged and
    reflected on the shard so the UI surfaces them — never re-raised,
    since nothing is awaiting us."""
    try:
        async with AgentClient(host=host) as agent:
            await agent.teardown(decky_id)
    except Exception as exc:
        log.exception(
            "swarm.teardown background task failed host=%s decky=%s",
            host.get("name"), decky_id,
        )
        # Reflect the failure on the shard(s) — don't delete on failure,
        # the operator needs to see what went wrong and retry.
        try:
            shards = await repo.list_decky_shards(host["uuid"])
            for s in shards:
                if decky_id and s.get("decky_name") != decky_id:
                    continue
                await repo.upsert_decky_shard({
                    **s,
                    "state": "teardown_failed",
                    "last_error": str(exc)[:512],
                })
        except Exception:
            log.exception("swarm.teardown failed to record shard failure")
        return

    try:
        if decky_id:
            await repo.delete_decky_shard(decky_id)
        else:
            await repo.delete_decky_shards_for_host(host["uuid"])
    except Exception:
        log.exception("swarm.teardown DB cleanup failed (agent call succeeded)")


@router.post(
    "/hosts/{uuid}/teardown",
    response_model=TeardownHostResponse,
    status_code=status.HTTP_202_ACCEPTED,
    tags=["Swarm Management"],
)
async def teardown_host(
    uuid: str,
    req: TeardownHostRequest,
    admin: dict = Depends(require_admin),
    repo: BaseRepository = Depends(get_repo),
) -> TeardownHostResponse:
    host = await repo.get_swarm_host_by_uuid(uuid)
    if host is None:
        raise HTTPException(status_code=404, detail="host not found")

    await _mark_tearing_down(repo, uuid, req.decky_id)

    # Fire-and-forget: asyncio.create_task (not BackgroundTasks) so the
    # task runs independently of this request's lifecycle — the operator
    # can queue another teardown the moment this one returns 202 without
    # waiting for any per-request cleanup phase.
    _spawn(_run_teardown(host, repo, req.decky_id))

    return TeardownHostResponse(
        host_uuid=uuid,
        host_name=host.get("name") or "",
        decky_id=req.decky_id,
        accepted=True,
        detail="teardown queued",
    )
