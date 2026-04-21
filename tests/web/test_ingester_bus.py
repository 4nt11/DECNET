"""Bus wiring for the ingester (DEBT-031, worker 6).

The ingester emits one ``system.log`` event per DB-committed batch via
``_publish_batch``.  Per-line noise lives on the collector side; the
ingester's job is to signal "N rows landed in the DB up to offset P" so
heartbeat / federation consumers can tail DB progress without polling
the state table.
"""
from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from decnet.bus.fake import FakeBus
from decnet.web.ingester import _publish_batch


@pytest_asyncio.fixture
async def bus() -> FakeBus:
    b = FakeBus()
    await b.connect()
    yield b
    await b.close()


@pytest.mark.asyncio
async def test_publish_batch_fires_on_nonempty_flush(bus: FakeBus) -> None:
    sub = bus.subscribe("system.log")
    async with sub:
        await _publish_batch(bus, flushed=17, position=4096)
        event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)

    assert event.topic == "system.log"
    assert event.type == "batch_committed"
    assert event.payload == {
        "component": "ingester",
        "flushed": 17,
        "position": 4096,
    }


@pytest.mark.asyncio
async def test_publish_batch_skips_zero_row_flush(bus: FakeBus) -> None:
    # An empty batch shouldn't pollute the topic — nothing to signal.
    sub = bus.subscribe("system.log")
    async with sub:
        await _publish_batch(bus, flushed=0, position=0)
        # Expect nothing within a short window.  asyncio.wait_for raises
        # TimeoutError when no event arrives.
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(sub.__anext__(), timeout=0.2)


@pytest.mark.asyncio
async def test_publish_batch_is_noop_when_bus_is_none() -> None:
    # Bus-disabled path: ingester passes bus=None into _publish_batch.
    # Must be a safe no-op; no exceptions, no hangs.
    await _publish_batch(None, flushed=5, position=123)


@pytest.mark.asyncio
async def test_publish_batch_swallows_bus_failures(monkeypatch) -> None:
    # A dead bus must never break the ingestion loop.
    class _ExplodingBus:
        async def publish(self, *_args, **_kwargs):
            raise RuntimeError("transport exploded")

    await _publish_batch(_ExplodingBus(), flushed=3, position=42)


@pytest.mark.asyncio
async def test_ingester_degrades_cleanly_when_bus_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from decnet.bus.factory import get_bus

    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")
    b = get_bus(client_name="ingester")
    await b.connect()
    await b.publish("system.log", {"component": "ingester"}, event_type="batch_committed")
    await b.close()
