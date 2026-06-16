# SPDX-License-Identifier: AGPL-3.0-or-later
"""SSE stream of identity-resolution events — one connection per viewer.

Subscribes to ``identity.>`` on the :class:`~decnet.bus.base.BaseBus` for
the duration of the request and forwards each matching bus event as a
Server-Sent Event to the browser. Emits a one-shot snapshot on connect
(current paginated identity list) so the client doesn't need a separate
fetch to initialise.

Authorization mirrors :mod:`decnet.web.router.topology.api_events` — a
single-use opaque ticket passed via the ``?ticket=`` query parameter
(EventSource can't set arbitrary headers) + ``require_stream_viewer``
role gate.

The endpoint is broadly scoped (every identity event, not per-uuid)
because both ``AttackerDetail`` and ``IdentityDetail`` need the same
firehose: a bare ``AttackerDetail`` watches for ``identity.formed``
events that finally bind its ``identity_id``, and ``IdentityDetail``
watches for ``observation.linked`` / ``merged`` / ``unmerged`` against
the identity it's rendering. A per-uuid filter would force the client
to know its identity before subscribing, which it doesn't always.
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

log = get_logger("api.identities.events")

router = APIRouter()

_KEEPALIVE_SECS = 15.0
_SNAPSHOT_LIMIT = 50


def _format_sse(event_name: str, data: dict) -> str:
    return f"event: {event_name}\ndata: {orjson.dumps(data).decode()}\n\n"


@router.get(
    "/identities/events",
    tags=["Identity Resolution"],
    responses={
        200: {
            "content": {"text/event-stream": {}},
            "description": "SSE stream of identity-resolution events",
        },
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        429: {"description": "Per-user SSE connection cap reached"},
    },
)
@_traced("api.identities.events")
async def api_identities_events(
    request: Request,
    user: dict = Depends(require_stream_viewer),
) -> StreamingResponse:
    # Event types emitted: snapshot, formed, observation.linked,
    # merged, unmerged. All wrap bus events whose payload is also
    # reachable via viewer-gated REST (GET /identities/*).
    snapshot = await repo.list_identities(limit=_SNAPSHOT_LIMIT, offset=0)

    async def generator() -> AsyncGenerator[str, None]:
        async with sse_connection_slot(user["uuid"]):
            yield ": keepalive\n\n"
            yield _format_sse("snapshot", {"identities": snapshot})

            bus = await get_app_bus()
            if bus is None:
                # Bus disabled / unreachable — keep the connection
                # alive so the client doesn't reconnect-storm; it can
                # re-poll the REST API on its own timer.
                while not await request.is_disconnected():
                    try:
                        await asyncio.sleep(_KEEPALIVE_SECS)
                    except asyncio.CancelledError:
                        break
                    yield ": keepalive\n\n"
                return

            sub = bus.subscribe(f"{_topics.IDENTITY}.>")
            try:
                async with sub:
                    sub_iter = sub.__aiter__()
                    while True:
                        if await request.is_disconnected():
                            break
                        next_task = asyncio.ensure_future(sub_iter.__anext__())
                        try:
                            event = await asyncio.wait_for(
                                next_task, timeout=_KEEPALIVE_SECS,
                            )
                        except asyncio.TimeoutError:
                            next_task.cancel()
                            yield ": keepalive\n\n"
                            continue
                        except StopAsyncIteration:
                            break
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
                log.exception("identity events stream crashed")
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

    ``identity.formed``             → ``formed``
    ``identity.observation.linked`` → ``observation.linked``
    Pass-through preserves dotted leaves so the frontend can switch on
    a stable name.
    """
    if topic.startswith(f"{_topics.IDENTITY}."):
        return topic[len(_topics.IDENTITY) + 1:]
    return topic
