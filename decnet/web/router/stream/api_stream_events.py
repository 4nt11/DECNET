# SPDX-License-Identifier: AGPL-3.0-or-later
import asyncio

import orjson
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from decnet.env import DECNET_DEVELOPER
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced, get_tracer as _get_tracer
from decnet.web.dependencies import require_stream_viewer, repo
from decnet.web.sse_limits import sse_connection_slot

log = get_logger("api")

router = APIRouter()


def _build_trace_links(logs: list[dict]) -> list:
    """Build OTEL span links from persisted trace_id/span_id in log rows.

    Returns an empty list when tracing is disabled (no OTEL imports).
    """
    try:
        from opentelemetry.trace import Link, SpanContext, TraceFlags
    except ImportError:
        return []
    links: list[Link] = []
    for entry in logs:
        tid = entry.get("trace_id")
        sid = entry.get("span_id")
        if not tid or not sid or tid == "0":
            continue
        try:
            ctx = SpanContext(
                trace_id=int(tid, 16),
                span_id=int(sid, 16),
                is_remote=True,
                trace_flags=TraceFlags(TraceFlags.SAMPLED),
            )
            links.append(Link(ctx))
        except (ValueError, TypeError):
            continue
    return links


@router.get("/stream", tags=["Observability"],
    responses={
        200: {
            "content": {"text/event-stream": {}},
            "description": "Real-time Server-Sent Events (SSE) stream"
        },
        401: {"description": "Could not validate credentials"},
        403: {"description": "Insufficient permissions"},
        422: {"description": "Validation error"},
        429: {"description": "Per-user SSE connection cap reached"},
    },
)
@_traced("api.stream_events")
async def stream_events(
    request: Request,
    last_event_id: int = Query(0, alias="lastEventId"),
    search: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    max_output: Optional[int] = Query(None, alias="maxOutput"),
    user: dict = Depends(require_stream_viewer)
) -> StreamingResponse:
    # Event types emitted on this stream: logs, stats, histogram.
    # All three are viewer-safe — same data is reachable via /logs and
    # /stats (viewer-gated REST). Adding a new event family here
    # requires a threat-model review for F6/I (role leakage).

    async def event_generator() -> AsyncGenerator[str, None]:
        async with sse_connection_slot(user["uuid"]):
            # Prefetch the initial snapshot before the first yield.
            # With asyncmy (pure async TCP I/O), a DB await AFTER the first
            # yield races with the HTTP write callback; running DB reads
            # here (pre-yield, normal coroutine context) avoids that.
            # aiosqlite is immune because SQLite runs on a worker thread.
            _start_id = last_event_id if last_event_id != 0 else await repo.get_max_log_id()
            _initial_stats = await repo.get_stats_summary()
            _initial_histogram = await repo.get_log_histogram(
                search=search, start_time=start_time, end_time=end_time, interval_minutes=15,
            )
            last_id = _start_id
            stats_interval_sec = 10
            loops_since_stats = 0
            emitted_chunks = 0
            try:
                yield ": keepalive\n\n"  # flush headers immediately

                # Emit pre-fetched initial snapshot — no DB calls in generator until the loop
                yield f"event: message\ndata: {orjson.dumps({'type': 'stats', 'data': _initial_stats}).decode()}\n\n"
                yield f"event: message\ndata: {orjson.dumps({'type': 'histogram', 'data': _initial_histogram}).decode()}\n\n"

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
                        # Create a span linking back to the ingestion traces
                        # stored in each log row, closing the pipeline gap.
                        _links = _build_trace_links(new_logs)
                        _tracer = _get_tracer("sse")
                        with _tracer.start_as_current_span(
                            "sse.emit_logs", links=_links,
                            attributes={"log_count": len(new_logs)},
                        ):
                            yield f"event: message\ndata: {orjson.dumps({'type': 'logs', 'data': new_logs}).decode()}\n\n"
                        loops_since_stats = stats_interval_sec

                    if loops_since_stats >= stats_interval_sec:
                        stats = await repo.get_stats_summary()
                        yield f"event: message\ndata: {orjson.dumps({'type': 'stats', 'data': stats}).decode()}\n\n"
                        histogram = await repo.get_log_histogram(
                            search=search, start_time=start_time,
                            end_time=end_time, interval_minutes=15,
                        )
                        yield f"event: message\ndata: {orjson.dumps({'type': 'histogram', 'data': histogram}).decode()}\n\n"
                        loops_since_stats = 0

                    loops_since_stats += 1

                    await asyncio.sleep(1)
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception("SSE stream error for user %s", last_event_id)
                yield f"event: error\ndata: {orjson.dumps({'type': 'error', 'message': 'Stream interrupted'}).decode()}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
