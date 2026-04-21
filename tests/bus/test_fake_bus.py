"""Tests for :class:`decnet.bus.fake.FakeBus` and :class:`NullBus`."""
from __future__ import annotations

import asyncio

import pytest

from decnet.bus.fake import FakeBus, NullBus


async def _collect(sub, n: int, timeout: float = 1.0) -> list:
    out = []
    try:
        async with asyncio.timeout(timeout):
            async for event in sub:
                out.append(event)
                if len(out) >= n:
                    break
    except TimeoutError:
        pass
    return out


class TestFakeBus:
    async def test_publish_delivers_to_exact_match(self, fake_bus: FakeBus) -> None:
        sub = fake_bus.subscribe("topology.abc.status")
        async with sub:
            await fake_bus.publish("topology.abc.status", {"status": "active"})
            events = await _collect(sub, 1)
        assert len(events) == 1
        assert events[0].payload == {"status": "active"}

    async def test_publish_delivers_to_wildcard(self, fake_bus: FakeBus) -> None:
        sub = fake_bus.subscribe("topology.*.mutation.*")
        async with sub:
            await fake_bus.publish("topology.t1.mutation.applied", {"id": 1})
            await fake_bus.publish("topology.t2.mutation.failed", {"id": 2})
            await fake_bus.publish("decky.x.state", {"state": "running"})  # should not match
            events = await _collect(sub, 2)
        assert len(events) == 2
        assert {e.payload["id"] for e in events} == {1, 2}

    async def test_multiple_subscribers_each_get_copy(self, fake_bus: FakeBus) -> None:
        sub_a = fake_bus.subscribe("topology.>")
        sub_b = fake_bus.subscribe("topology.>")
        async with sub_a, sub_b:
            await fake_bus.publish("topology.abc.status", {"status": "active"})
            a = await _collect(sub_a, 1)
            b = await _collect(sub_b, 1)
        assert len(a) == 1
        assert len(b) == 1

    async def test_subscription_close_unblocks_iter(self, fake_bus: FakeBus) -> None:
        sub = fake_bus.subscribe("topology.>")

        async def consume() -> list:
            out = []
            async for event in sub:
                out.append(event)
            return out

        task = asyncio.create_task(consume())
        await asyncio.sleep(0.01)  # let task block on queue.get()
        await sub.aclose()
        events = await asyncio.wait_for(task, timeout=0.5)
        assert events == []

    async def test_close_is_idempotent(self, fake_bus: FakeBus) -> None:
        await fake_bus.close()
        await fake_bus.close()  # second call must not raise

    async def test_publish_on_closed_raises(self, fake_bus: FakeBus) -> None:
        await fake_bus.close()
        with pytest.raises(RuntimeError):
            await fake_bus.publish("x", {})
        with pytest.raises(RuntimeError):
            fake_bus.subscribe("x")

    async def test_backpressure_drops_oldest(self) -> None:
        bus = FakeBus(queue_size=2)
        await bus.connect()
        try:
            sub = bus.subscribe("t")
            # Don't consume; publish 5 — queue holds at most 2, oldest dropped.
            for i in range(5):
                await bus.publish("t", {"i": i})
            events = await _collect(sub, 2, timeout=0.2)
            assert len(events) == 2
            # We kept the 2 most recent.
            assert events[-1].payload["i"] == 4
        finally:
            await bus.close()


class TestNullBus:
    async def test_publish_is_noop(self) -> None:
        bus = NullBus()
        await bus.connect()
        await bus.publish("anything", {"x": 1})
        await bus.close()

    async def test_subscribe_yields_nothing(self) -> None:
        bus = NullBus()
        sub = bus.subscribe("topology.>")
        async with sub:
            # Iteration must stop immediately.
            events = [e async for e in sub]
        assert events == []
