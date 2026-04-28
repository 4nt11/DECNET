"""Per-user concurrent SSE connection gate.

SSE connections are long-lived — a client that opens one per tab
forever can exhaust API workers. Module-level dict + async lock keeps
the fast path cheap (a dict lookup) while the lock keeps check-and-
increment atomic across concurrent handshakes.

The slot must wrap the generator's own lifetime, not just the handler
call, because StreamingResponse returns before the generator body
runs. Call it as the first statement inside the generator — an
HTTPException raised before the first yield bubbles back to the client
as a normal HTTP response.
"""
from __future__ import annotations

import asyncio
import os
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import HTTPException, status

DEFAULT_CAP = 5
_MAX_PER_USER = int(os.environ.get("DECNET_SSE_MAX_PER_USER", DEFAULT_CAP))
_counts: dict[str, int] = defaultdict(int)
_lock: asyncio.Lock | None = None


def _get_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


def _reset_for_tests() -> None:
    """Clear counters + lock between tests. The lock is rebuilt lazily
    so a fixture can reset state without worrying about event-loop
    binding from a previous test."""
    global _lock
    _counts.clear()
    _lock = None


def current_count(user_uuid: str) -> int:
    """Snapshot helper — tests and diagnostics only."""
    return _counts.get(user_uuid, 0)


@asynccontextmanager
async def sse_connection_slot(user_uuid: str):
    async with _get_lock():
        if _counts[user_uuid] >= _MAX_PER_USER:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"SSE connection limit ({_MAX_PER_USER}) reached",
            )
        _counts[user_uuid] += 1
    try:
        yield
    finally:
        async with _get_lock():
            _counts[user_uuid] -= 1
            if _counts[user_uuid] <= 0:
                del _counts[user_uuid]
