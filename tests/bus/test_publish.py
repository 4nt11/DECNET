# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for :mod:`decnet.bus.publish`.

The whole point of ``publish_safely`` is that it never raises back at the
caller.  These tests pin that contract: ``None`` bus is a no-op, a real
bus publishes, and a raising bus is swallowed + logged.
"""
from __future__ import annotations

import logging

import pytest

from decnet.bus.base import BaseBus, Event, Subscription
from decnet.bus.fake import FakeBus
from decnet.bus.publish import publish_safely


class _ExplodingBus(BaseBus):
    """Minimal bus whose ``publish`` always raises."""

    async def connect(self) -> None:  # pragma: no cover - trivial
        return None

    async def publish(self, topic, payload, *, event_type=""):
        raise RuntimeError("transport exploded")

    def subscribe(self, pattern: str) -> Subscription:  # pragma: no cover
        raise NotImplementedError

    async def close(self) -> None:  # pragma: no cover - trivial
        return None


@pytest.mark.asyncio
async def test_publish_safely_none_bus_is_noop() -> None:
    # Must not raise.  A worker that couldn't connect at startup passes
    # bus=None and expects every call to silently no-op.
    await publish_safely(None, "system.log", {"msg": "hi"})


@pytest.mark.asyncio
async def test_publish_safely_delivers_on_live_bus() -> None:
    bus = FakeBus()
    await bus.connect()
    try:
        sub = bus.subscribe("system.log")
        async with sub:
            await publish_safely(bus, "system.log", {"msg": "hi"}, event_type="log")
            event = await sub.__anext__()
            assert isinstance(event, Event)
            assert event.topic == "system.log"
            assert event.type == "log"
            assert event.payload == {"msg": "hi"}
    finally:
        await bus.close()


@pytest.mark.asyncio
async def test_publish_safely_swallows_transport_errors(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="bus.publish")
    # The exploding bus would crash the caller without publish_safely.
    # After wrapping, the caller sees nothing but a log line.
    await publish_safely(_ExplodingBus(), "system.log", {"msg": "hi"})
    assert any("bus publish failed" in rec.message for rec in caplog.records)
