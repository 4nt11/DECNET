import json
import asyncio
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from decnet.web.dependencies import get_current_user, repo

router = APIRouter()


@router.get("/stream", tags=["Observability"])
async def stream_events(
    request: Request, 
    last_event_id: int = Query(0, alias="lastEventId"), 
    search: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    current_user: str = Depends(get_current_user)
) -> StreamingResponse:
    
    async def event_generator() -> AsyncGenerator[str, None]:
        # Start tracking from the provided ID, or current max if 0
        last_id = last_event_id
        if last_id == 0:
            last_id = await repo.get_max_log_id()
            
        stats_interval_sec = 10
        loops_since_stats = 0
        
        while True:
            if await request.is_disconnected():
                break

            # Poll for new logs
            new_logs = await repo.get_logs_after_id(last_id, limit=50, search=search, start_time=start_time, end_time=end_time)
            if new_logs:
                # Update last_id to the max id in the fetched batch
                last_id = max(log["id"] for log in new_logs)
                payload = json.dumps({"type": "logs", "data": new_logs})
                yield f"event: message\ndata: {payload}\n\n"
                
                # If we have new logs, stats probably changed, so force a stats update
                loops_since_stats = stats_interval_sec
            
            # Periodically poll for stats
            if loops_since_stats >= stats_interval_sec:
                stats = await repo.get_stats_summary()
                payload = json.dumps({"type": "stats", "data": stats})
                yield f"event: message\ndata: {payload}\n\n"

                # Also yield histogram
                histogram = await repo.get_log_histogram(search=search, start_time=start_time, end_time=end_time, interval_minutes=15)
                hist_payload = json.dumps({"type": "histogram", "data": histogram})
                yield f"event: message\ndata: {hist_payload}\n\n"

                loops_since_stats = 0
                
            loops_since_stats += 1
            await asyncio.sleep(1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
