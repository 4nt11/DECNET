# SPDX-License-Identifier: AGPL-3.0-or-later
"""W.3 bus-path drain tests.

Exercises ``_drain_behave_queue`` directly without the asyncio worker
loop. The handler is unit-tested in
``test_handler_session_ended.py``; this file pins the queue-drain
plumbing (Event unwrapping, isolation against handler exceptions,
empty-queue no-op).
"""
from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from decnet.profiler.worker import _drain_behave_queue


async def _make_event(payload: dict[str, Any]):
    """Build a minimal Event-like object the drain expects."""
    ev = MagicMock()
    ev.topic = "attacker.session.ended"
    ev.payload = payload
    return ev


async def test_drain_empty_queue_is_noop() -> None:
    repo = AsyncMock()
    queue: asyncio.Queue = asyncio.Queue()
    await _drain_behave_queue(repo, queue, None)
    repo.has_observations_for_evidence.assert_not_awaited()


async def test_drain_skips_none_sentinel() -> None:
    repo = AsyncMock()
    queue: asyncio.Queue = asyncio.Queue()
    await queue.put(None)
    await _drain_behave_queue(repo, queue, None)
    repo.has_observations_for_evidence.assert_not_awaited()


async def test_drain_passes_event_payload_to_handler(monkeypatch) -> None:
    """The drain unwraps Event.payload and feeds it to the handler."""
    captured: list[dict[str, Any]] = []

    async def _fake_handler(repo, payload, publish):
        captured.append(payload)
        return 0

    monkeypatch.setattr(
        "decnet.profiler.worker.handle_session_ended", _fake_handler,
    )
    repo = AsyncMock()
    queue: asyncio.Queue = asyncio.Queue()
    ev = await _make_event({"session_id": "abc", "decky_id": "d"})
    await queue.put((ev.topic, ev))
    await _drain_behave_queue(repo, queue, None)
    assert captured == [{"session_id": "abc", "decky_id": "d"}]


async def test_drain_isolates_handler_exception(monkeypatch) -> None:
    """A handler that raises must not crash subsequent events."""
    call_count = 0

    async def _maybe_blowing_handler(repo, payload, publish):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("handler exploded")
        return 0

    monkeypatch.setattr(
        "decnet.profiler.worker.handle_session_ended",
        _maybe_blowing_handler,
    )
    repo = AsyncMock()
    queue: asyncio.Queue = asyncio.Queue()
    ev1 = await _make_event({"session_id": "a"})
    ev2 = await _make_event({"session_id": "b"})
    await queue.put((ev1.topic, ev1))
    await queue.put((ev2.topic, ev2))

    # Should not raise; both events should be drained.
    await _drain_behave_queue(repo, queue, None)
    assert call_count == 2
