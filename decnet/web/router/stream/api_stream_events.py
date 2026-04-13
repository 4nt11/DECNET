import json
import asyncio
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from decnet.env import DECNET_DEVELOPER
from decnet.logging import get_logger
from decnet.web.dependencies import get_stream_user, repo

log = get_logger("api")

router = APIRouter()


@router.get("/stream", tags=["Observability"],
    responses={
        200: {
            "content": {"text/event-stream": {}},
            "description": "Real-time Server-Sent Events (SSE) stream"
        },
        401: {"description": "Could not validate credentials"},
        422: {"description": "Validation error"}
    },
)
async def stream_events(
    request: Request,
    last_event_id: int = Query(0, alias="lastEventId"),
    search: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_output: Optional[int] = Query(None, alias="maxOutput"),
    current_user: str = Depends(get_stream_user)
) -> StreamingResponse:

    async def event_generator() -> AsyncGenerator[str, None]:
        last_id = last_event_id
        stats_interval_sec = 10
        loops_since_stats = 0
        emitted_chunks = 0
        try:
            if last_id == 0:
                last_id = await repo.get_max_log_id()

            # Emit initial snapshot immediately so the client never needs to poll /stats
            stats = await repo.get_stats_summary()
            yield f"event: message\ndata: {json.dumps({'type': 'stats', 'data': stats})}\n\n"
            histogram = await repo.get_log_histogram(
                search=search, start_time=start_time,
                end_time=end_time, interval_minutes=15,
            )
            yield f"event: message\ndata: {json.dumps({'type': 'histogram', 'data': histogram})}\n\n"

            while True:
                if DECNET_DEVELOPER and max_output is not None:
                    emitted_chunks += 1
                    if emitted_chunks > max_output:
                        log.debug("Developer mode: max_output reached (%d), closing stream", max_output)
                        break

                if await request.is_disconnected():
                    break

                new_logs = await repo.get_logs_after_id(
                    last_id, limit=50, search=search,
                    start_time=start_time, end_time=end_time,
                )
                if new_logs:
                    last_id = max(entry["id"] for entry in new_logs)
                    yield f"event: message\ndata: {json.dumps({'type': 'logs', 'data': new_logs})}\n\n"
                    loops_since_stats = stats_interval_sec

                if loops_since_stats >= stats_interval_sec:
                    stats = await repo.get_stats_summary()
                    yield f"event: message\ndata: {json.dumps({'type': 'stats', 'data': stats})}\n\n"
                    histogram = await repo.get_log_histogram(
                        search=search, start_time=start_time,
                        end_time=end_time, interval_minutes=15,
                    )
                    yield f"event: message\ndata: {json.dumps({'type': 'histogram', 'data': histogram})}\n\n"
                    loops_since_stats = 0

                loops_since_stats += 1

                await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass
        except Exception:
            log.exception("SSE stream error for user %s", last_event_id)
            yield f"event: error\ndata: {json.dumps({'type': 'error', 'message': 'Stream interrupted'})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")
