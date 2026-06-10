# SPDX-License-Identifier: AGPL-3.0-or-later
"""SSE stream of topology lifecycle events — one connection per editor.

Subscribes to ``topology.<id>.>`` on the :class:`~decnet.bus.base.BaseBus`
for the duration of the request and forwards each matching bus event as
a Server-Sent Event to the browser.  Emits a one-shot snapshot on connect
(current status + any in-flight mutations) so the client doesn't need a
separate fetch to initialise the "pending" buffer.

Authorization matches :mod:`decnet.web.router.stream.api_stream_events`
— a single-use opaque ticket passed via the ``?ticket=`` query
parameter (EventSource can't set arbitrary headers) +
``require_stream_viewer`` role gate.  The
per-topology 404 is enforced after auth so existence probes can't leak
a topology id to an unauthenticated caller.
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

from ._guards import get_topology_or_404

log = get_logger("api.topology.events")

router = APIRouter()

_KEEPALIVE_SECS = 15.0
_IN_FLIGHT_STATES = ("pending", "applying")


def _format_sse(event_name: str, data: dict) -> str:
    """Build one SSE frame: ``event: <name>\\ndata: <json>\\n\\n``."""
    return f"event: {event_name}\ndata: {orjson.dumps(data).decode()}\n\n"


@router.get(
    "/{topology_id}/events",
    tags=["MazeNET Topologies"],
    responses={
        200: {
            "content": {"text/event-stream": {}},
            "description": "SSE stream of mutation and status events for one topology",
        },
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Topology not found"},
        429: {"description": "Per-user SSE connection cap reached"},
    },
)
@_traced("api.topology.events")
async def api_topology_events(
    topology_id: str,
    request: Request,
    user: dict = Depends(require_stream_viewer),
) -> StreamingResponse:
    # Event types emitted: snapshot, status, mutation.{enqueued,
    # applying,applied,failed}. All wrap bus events whose payload is
    # also reachable via viewer-gated REST (GET /topologies/{id},
    # GET /topologies/{id}/mutations). Adding a new event family here
    # requires a threat-model review for F6/I (role leakage).
    topo = await get_topology_or_404(topology_id)
    snapshot_status = topo.status
    in_flight: list[dict] = []
    for state in _IN_FLIGHT_STATES:
        in_flight.extend(await repo.list_topology_mutations(topology_id, state=state))

    async def generator() -> AsyncGenerator[str, None]:
        async with sse_connection_slot(user["uuid"]):
            # Flush headers immediately so the browser's EventSource sees a
            # live connection before the first real event arrives.
            yield ": keepalive\n\n"

            # One-shot snapshot — pair the current topology status with any
            # mutations the mutator is still holding, so the client buffer
            # can render an accurate "already in flight" state.
            yield _format_sse("snapshot", {
                "topology_id": topology_id,
                "status": snapshot_status,
                "in_flight": in_flight,
            })

            bus = await get_app_bus()
            if bus is None:
                # Bus disabled (NullBus) or unreachable.  The snapshot is
                # still useful; we idle on keepalives so the client stays
                # connected and will re-poll on its own timers.
                while not await request.is_disconnected():
                    try:
                        await asyncio.sleep(_KEEPALIVE_SECS)
                    except asyncio.CancelledError:
                        break
                    yield ": keepalive\n\n"
                return

            # Two subscriptions, merged through an asyncio.Queue:
            #
            #   topology.<id>.>  — lifecycle (status, mutation.*).
            #   decky.>          — per-decky events, filtered to this
            #                      topology by the event's payload.
            #
            # Decky events carry ``topology_id`` in their payload (see
            # decnet.engine.services_live._publish); we discard ones
            # that don't belong to this stream so a fleet decky sharing
            # a name with a topology decky doesn't leak across.
            topo_sub = bus.subscribe(f"{_topics.TOPOLOGY}.{topology_id}.>")
            decky_sub = bus.subscribe(f"{_topics.DECKY}.>")
            queue: asyncio.Queue = asyncio.Queue(maxsize=256)

            async def _pump(sub, *, only_topology: bool = False) -> None:
                async with sub:
                    async for ev in sub:
                        if only_topology:
                            payload = ev.payload or {}
                            if payload.get("topology_id") != topology_id:
                                continue
                        try:
                            queue.put_nowait(ev)
                        except asyncio.QueueFull:
                            # Drop on overflow rather than backpressuring
                            # the bus; the snapshot + reconnect path will
                            # cover any gap a slow consumer creates.
                            pass

            topo_task = asyncio.create_task(_pump(topo_sub))
            decky_task = asyncio.create_task(_pump(decky_sub, only_topology=True))
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
                log.exception("topology events stream crashed topology_id=%s", topology_id)
                yield _format_sse("error", {"message": "Stream interrupted"})
            finally:
                topo_task.cancel()
                decky_task.cancel()

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


def _sse_name_for(topic: str) -> str:
    """Derive an SSE ``event:`` name from a bus topic.

    ``topology.<id>.mutation.applied``        → ``mutation.applied``
    ``topology.<id>.status``                  → ``status``
    ``decky.<name>.service_added``            → ``decky.service_added``
    ``decky.<name>.service_removed``          → ``decky.service_removed``
    Anything else is passed through unchanged so future topic families
    don't silently collapse onto a generic bucket.

    Bus topic segments are NATS-style tokens — no dots inside a segment
    — which is why the leaf is ``service_added`` (underscore) here and
    on the wire, not ``service.added``.  The frontend's
    ``useTopologyStream`` listens on the underscore form too.
    """
    parts = topic.split(".", 2)
    if len(parts) < 3:
        return topic
    head, _ident, tail = parts
    # Decky events: keep the ``decky.`` prefix so the frontend
    # discriminates them from topology-lifecycle events that happen to
    # share an event name (e.g. ``status``).
    if head == _topics.DECKY:
        return f"{_topics.DECKY}.{tail}"
    return tail
