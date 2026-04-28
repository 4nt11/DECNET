"""Module-level session helpers shared by every repository mixin.

``_safe_session`` and ``_detach_close`` make session cleanup robust under
client-cancellation. See ``_detach_close`` for the full rationale.

``_serialize_json_fields`` / ``_deserialize_json_fields`` live here
because they're used across multiple domain mixins (fleet, topology,
…); putting them in a single mixin would force the others to inherit
that mixin or import a free function — both worse than a shared helper.
"""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any

import orjson
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from decnet.logging import get_logger

_log = get_logger("db.pool")

# Hold strong refs to in-flight cleanup tasks so they aren't GC'd mid-run.
_cleanup_tasks: set[asyncio.Task] = set()


def _detach_close(session: AsyncSession) -> None:
    """Hand session cleanup to a fresh task so the caller's cancellation
    doesn't interrupt it.

    ``asyncio.shield`` doesn't help on the exception path: shield prevents
    *other* tasks from cancelling the inner coroutine, but if the *current*
    task is already cancelled, its next ``await`` re-raises
    ``CancelledError`` as soon as the inner coroutine yields.  That's what
    happens when uvicorn cancels a request mid-query — the rollback inside
    ``session.close()`` can't complete, and the aiomysql connection is
    orphaned (pool logs "non-checked-in connection" on GC).

    A fresh task isn't subject to the caller's pending cancellation, so
    ``close()`` (or the ``invalidate()`` fallback for a dead connection)
    runs to completion and the pool reclaims the connection promptly.

    Fire-and-forget on purpose: the caller is already unwinding and must
    not wait on cleanup.
    """
    async def _cleanup() -> None:
        try:
            await session.close()
        except BaseException:
            try:
                session.sync_session.invalidate()
            except BaseException:
                _log.debug("detach-close: invalidate failed", exc_info=True)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        # No running loop (shutdown path) — best-effort sync invalidate.
        try:
            session.sync_session.invalidate()
        except BaseException:
            _log.debug("detach-close: no-loop invalidate failed", exc_info=True)
        return
    task = loop.create_task(_cleanup())
    _cleanup_tasks.add(task)
    # Consume any exception to silence "Task exception was never retrieved".
    task.add_done_callback(lambda t: (_cleanup_tasks.discard(t), t.exception()))


@asynccontextmanager
async def _safe_session(factory: async_sessionmaker[AsyncSession]):
    """Session context manager that keeps close() reliable under cancellation.

    Success path: await close() inline so the caller observes cleanup
    (commit visibility, connection release) before proceeding.

    Exception path (includes CancelledError from client disconnects):
    detach close() to a fresh task.  The caller is unwinding and its
    own cancellation would abort an inline close mid-rollback, leaving
    the aiomysql connection orphaned.
    """
    session = factory()
    try:
        yield session
    except BaseException:
        _detach_close(session)
        raise
    else:
        await session.close()


def _serialize_json_fields(data: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """Encode the named keys as JSON strings if they're not already."""
    out = dict(data)
    for k in keys:
        v = out.get(k)
        if v is not None and not isinstance(v, str):
            out[k] = orjson.dumps(v).decode()
    return out


def _deserialize_json_fields(d: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    """Decode the named JSON-string keys in place."""
    for k in keys:
        v = d.get(k)
        if isinstance(v, str):
            try:
                d[k] = json.loads(v)
            except (json.JSONDecodeError, TypeError):
                pass
    return d
