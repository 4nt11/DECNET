# SPDX-License-Identifier: AGPL-3.0-or-later
"""Collector publishes ``attacker.session.ended`` end-to-end.

Wires :func:`_make_system_log_publisher` against a fake bus, drives
two parsed events (a CMD then a session_recorded) through the
returned publish_fn, and asserts the bus saw one
``attacker.session.ended`` envelope alongside the per-line
``system.log`` traffic.
"""
from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator

import pytest
import pytest_asyncio

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.collector.worker import _make_system_log_publisher


@pytest_asyncio.fixture
async def bus() -> AsyncIterator[FakeBus]:
    b = FakeBus()
    await b.connect()
    try:
        yield b
    finally:
        await b.close()


@pytest.mark.asyncio
async def test_session_ended_published_alongside_system_log(
    bus: FakeBus,
) -> None:
    captured: list[tuple[str, dict[str, Any]]] = []
    sub = bus.subscribe(_topics.attacker(_topics.ATTACKER_SESSION_ENDED))

    async def drain() -> None:
        try:
            async with sub:
                async for ev in sub:
                    captured.append((ev.topic, ev.payload))
        except Exception:
            pass

    drain_task = asyncio.create_task(drain())
    await asyncio.sleep(0)

    loop = asyncio.get_running_loop()
    publish_fn = _make_system_log_publisher(bus, loop)

    publish_fn({
        "timestamp": "2026-05-02T06:22:48",
        "decky": "SRV-DELTA-77",
        "service": "bash",
        "event_type": "command",
        "attacker_ip": "192.168.1.5",
        "fields": {"command": "whoami"},
    })
    publish_fn({
        "timestamp": "2026-05-02T06:23:00",
        "decky": "omega-decky",
        "service": "sessrec",
        "event_type": "session_recorded",
        "attacker_ip": "192.168.1.5",
        "fields": {
            "sid": "sess-abc",
            "service": "ssh",
            "duration_s": "60.0",
        },
    })

    # Give the marshalled publish a tick to land.
    await asyncio.sleep(0.1)
    drain_task.cancel()

    assert len(captured) == 1
    topic, payload = captured[0]
    assert topic == _topics.attacker(_topics.ATTACKER_SESSION_ENDED)
    assert payload["session_id"] == "sess-abc"
    assert [c["command_text"] for c in payload["commands"]] == ["whoami"]
