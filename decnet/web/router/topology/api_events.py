"""SSE stream of topology lifecycle events — one connection per editor.

Subscribes to ``topology.<id>.>`` on the :class:`~decnet.bus.base.BaseBus`
for the duration of the request and forwards each matching bus event as
a Server-Sent Event to the browser.  Emits a one-shot snapshot on connect
(current status + any in-flight mutations) so the client doesn't need a
separate fetch to initialise the "pending" buffer.

Authorization matches :mod:`decnet.web.router.stream.api_stream_events`
— a JWT passed via the ``?token=`` query parameter (EventSource can't
set arbitrary headers) + ``require_stream_viewer`` role gate.  The
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
    },
)
@_traced("api.topology.events")
async def api_topology_events(
    topology_id: str,
    request: Request,
    _user: dict = Depends(require_stream_viewer),
) -> StreamingResponse:
    topo = await get_topology_or_404(topology_id)
    snapshot_status = topo["status"]
    in_flight: list[dict] = []
    for state in _IN_FLIGHT_STATES:
        in_flight.extend(await repo.list_topology_mutations(topology_id, state=state))

    async def generator() -> AsyncGenerator[str, None]:
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

        sub = bus.subscribe(f"{_topics.TOPOLOGY}.{topology_id}.>")
        try:
            async with sub:
                sub_iter = sub.__aiter__()
                while True:
                    if await request.is_disconnected():
                        break
                    next_task = asyncio.ensure_future(sub_iter.__anext__())
                    try:
                        event = await asyncio.wait_for(next_task, timeout=_KEEPALIVE_SECS)
                    except asyncio.TimeoutError:
                        next_task.cancel()
                        yield ": keepalive\n\n"
                        continue
                    except StopAsyncIteration:
                        break
                    # Map the bus event onto an SSE ``event:`` name that
                    # the frontend can switch on without parsing topics.
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

    ``topology.<id>.mutation.applied`` → ``mutation.applied``
    ``topology.<id>.status``           → ``status``
    Anything else is passed through unchanged so future topic families
    don't silently collapse onto a generic bucket.
    """
    parts = topic.split(".", 2)
    return parts[2] if len(parts) >= 3 else topic
