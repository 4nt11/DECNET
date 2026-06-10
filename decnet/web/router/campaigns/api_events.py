# SPDX-License-Identifier: AGPL-3.0-or-later
"""SSE stream of campaign events — one connection per viewer.

Subscribes to ``campaign.>`` on the bus for the duration of the
request and forwards each matching event as a Server-Sent Event.
Emits a one-shot snapshot on connect (current paginated campaign
list).

Mirror of :mod:`decnet.web.router.identities.api_events`. Auth:
single-use opaque ticket via ``?ticket=`` query param +
``require_stream_viewer`` role.
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

log = get_logger("api.campaigns.events")

router = APIRouter()

_KEEPALIVE_SECS = 15.0
_SNAPSHOT_LIMIT = 50


def _format_sse(event_name: str, data: dict) -> str:
    return f"event: {event_name}\ndata: {orjson.dumps(data).decode()}\n\n"


@router.get(
    "/campaigns/events",
    tags=["Campaign Clustering"],
    responses={
        200: {
            "content": {"text/event-stream": {}},
            "description": "SSE stream of campaign-clustering events",
        },
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        429: {"description": "Per-user SSE connection cap reached"},
    },
)
@_traced("api.campaigns.events")
async def api_campaigns_events(
    request: Request,
    user: dict = Depends(require_stream_viewer),
) -> StreamingResponse:
    # Event types: snapshot, formed, identity.assigned, merged, unmerged.
    snapshot = await repo.list_campaigns(limit=_SNAPSHOT_LIMIT, offset=0)

    async def generator() -> AsyncGenerator[str, None]:
        async with sse_connection_slot(user["uuid"]):
            yield ": keepalive\n\n"
            yield _format_sse("snapshot", {"campaigns": snapshot})

            bus = await get_app_bus()
            if bus is None:
                while not await request.is_disconnected():
                    try:
                        await asyncio.sleep(_KEEPALIVE_SECS)
                    except asyncio.CancelledError:
                        break
                    yield ": keepalive\n\n"
                return

            sub = bus.subscribe(f"{_topics.CAMPAIGN}.>")
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
                log.exception("campaign events stream crashed")
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
    """``campaign.formed`` → ``formed``;
    ``campaign.identity.assigned`` → ``identity.assigned``."""
    if topic.startswith(f"{_topics.CAMPAIGN}."):
        return topic[len(_topics.CAMPAIGN) + 1:]
    return topic
