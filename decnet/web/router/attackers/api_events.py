"""SSE stream of per-attacker behavioural events — one connection per
AttackerDetail page.

Subscribes to ``attacker.observation.>``,
``attacker.fingerprint_rotated`` and ``attacker.scored`` on the
:class:`~decnet.bus.base.BaseBus` for the duration of the request and
forwards each event whose payload's ``attacker_uuid`` matches this
stream's attacker. Emits a one-shot snapshot on connect (latest
observation per primitive) so the panel hydrates immediately.

Authorization mirrors :mod:`decnet.web.router.topology.api_events` —
JWT via the ``?token=`` query parameter (EventSource can't set
arbitrary headers) + ``require_stream_viewer`` role gate. The 404
fires after auth so an existence probe can't leak an attacker UUID
to an unauthenticated caller.

Per-attacker filter is keyed on the DECNET-side ``attacker_uuid``
denorm the profiler worker stamps onto every published payload (see
``BEHAVE-INTEGRATION.md`` §339-366 deviation note + Phase 5
amendment in ``decnet/profiler/behave_shell/_handler.py``).
"""
from __future__ import annotations

import asyncio
from typing import AsyncGenerator

import orjson
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from decnet.bus import topics as _topics
from decnet.bus.app import get_app_bus
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced
from decnet.web.dependencies import repo, require_stream_viewer
from decnet.web.sse_limits import sse_connection_slot

from ._guards import get_attacker_or_404

log = get_logger("api.attackers.events")

router = APIRouter()

_KEEPALIVE_SECS = 15.0
_QUEUE_MAX = 256


def _format_sse(event_name: str, data: dict) -> str:
    """Build one SSE frame: ``event: <name>\\ndata: <json>\\n\\n``."""
    return f"event: {event_name}\ndata: {orjson.dumps(data).decode()}\n\n"


def _sse_name_for(topic: str) -> str:
    """Derive an SSE ``event:`` name from a bus topic.

    ``attacker.observation.<primitive>`` → ``observation``
    (the primitive ride-along is in the payload, not the event name —
    a per-primitive event name would force the frontend hook to
    register 37+ listeners or know the registry. Single event name
    keeps the EventSource handler shape uniform.)

    ``attacker.fingerprint_rotated``     → ``fingerprint.rotated``
    ``attacker.scored``                  → ``attacker.scored``

    Anything else passes through unchanged so a future ``attacker.*``
    family doesn't silently collapse onto a generic bucket.
    """
    if topic.startswith("attacker.observation."):
        return "observation"
    if topic == f"{_topics.ATTACKER}.{_topics.ATTACKER_FINGERPRINT_ROTATED}":
        return "fingerprint.rotated"
    if topic == f"{_topics.ATTACKER}.{_topics.ATTACKER_SCORED}":
        return "attacker.scored"
    return topic


@router.get(
    "/attackers/{attacker_uuid}/events",
    tags=["Attacker Profiles"],
    responses={
        200: {
            "content": {"text/event-stream": {}},
            "description": "SSE stream of behavioural events for one attacker",
        },
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Attacker not found"},
        429: {"description": "Per-user SSE connection cap reached"},
    },
)
@_traced("api.attackers.events")
async def api_attacker_events(
    attacker_uuid: str,
    request: Request,
    user: dict = Depends(require_stream_viewer),
) -> StreamingResponse:
    # 404-after-auth so an existence probe can't enumerate attacker UUIDs.
    await get_attacker_or_404(attacker_uuid)

    snapshot_per_primitive = await repo.latest_observation_per_primitive(
        attacker_uuid,
    )
    snapshot_observations = [
        {"primitive": primitive, **payload}
        for primitive, payload in sorted(snapshot_per_primitive.items())
    ]

    async def generator() -> AsyncGenerator[str, None]:
        async with sse_connection_slot(user["uuid"]):
            # Flush headers immediately so the browser's EventSource
            # sees a live connection before the first real event.
            yield ": keepalive\n\n"

            yield _format_sse("snapshot", {
                "attacker_uuid": attacker_uuid,
                "observations": snapshot_observations,
            })

            bus = await get_app_bus()
            if bus is None:
                # Bus disabled (NullBus) or unreachable. The snapshot
                # is still useful; idle on keepalives so the client
                # stays connected and re-polls on its own timers.
                while not await request.is_disconnected():
                    try:
                        await asyncio.sleep(_KEEPALIVE_SECS)
                    except asyncio.CancelledError:
                        break
                    yield ": keepalive\n\n"
                return

            # Three subscriptions, merged through one queue. Per-attacker
            # filter on payload["attacker_uuid"] — the profiler worker
            # stamps it on every published payload (Phase 5 amendment).
            obs_sub = bus.subscribe(f"{_topics.ATTACKER}.{_topics.ATTACKER_OBSERVATION_PREFIX}.>")
            fp_sub = bus.subscribe(
                f"{_topics.ATTACKER}.{_topics.ATTACKER_FINGERPRINT_ROTATED}",
            )
            score_sub = bus.subscribe(
                f"{_topics.ATTACKER}.{_topics.ATTACKER_SCORED}",
            )
            queue: asyncio.Queue = asyncio.Queue(maxsize=_QUEUE_MAX)

            async def _pump(sub) -> None:
                async with sub:
                    async for ev in sub:
                        payload = ev.payload or {}
                        if payload.get("attacker_uuid") != attacker_uuid:
                            continue
                        try:
                            queue.put_nowait(ev)
                        except asyncio.QueueFull:
                            # Drop on overflow rather than backpressuring
                            # the bus; the snapshot + reconnect path will
                            # cover any gap a slow consumer creates.
                            pass

            tasks = [
                asyncio.create_task(_pump(obs_sub)),
                asyncio.create_task(_pump(fp_sub)),
                asyncio.create_task(_pump(score_sub)),
            ]
            try:
                while True:
                    if await request.is_disconnected():
                        break
                    try:
                        event = await asyncio.wait_for(
                            queue.get(), timeout=_KEEPALIVE_SECS,
                        )
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
                        continue
                    yield _format_sse(
                        _sse_name_for(event.topic),
                        {
                            "topic": event.topic,
                            "type": event.type,
                            "ts": event.ts,
                            "payload": event.payload,
                        },
                    )
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception(
                    "attacker events stream crashed attacker_uuid=%s",
                    attacker_uuid,
                )
                yield _format_sse("error", {"message": "Stream interrupted"})
            finally:
                for t in tasks:
                    t.cancel()

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
