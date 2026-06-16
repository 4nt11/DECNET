# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared ``run_health_heartbeat`` helper (DEBT-031 workers 7–9).

Three workers (agent, forwarder, updater) publish identical
``system.<worker>.health`` heartbeats.  Rather than copy the loop three
times, ``decnet.bus.publish.run_health_heartbeat`` carries it.  These
tests pin:

* topic is ``system.<worker>.health`` via the builder;
* payload carries worker name and monotonic-ish timestamp;
* ``extra()`` hook merges per-worker fields;
* ``None`` bus yields a benign no-op loop (still cancellable);
* ``extra()`` failure doesn't break the tick.
"""
from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from decnet.bus.fake import FakeBus
from decnet.bus.publish import run_health_heartbeat


@pytest_asyncio.fixture
async def bus() -> FakeBus:
    b = FakeBus()
    await b.connect()
    yield b
    await b.close()


@pytest.mark.asyncio
async def test_heartbeat_publishes_under_system_worker_health(bus: FakeBus) -> None:
    task = asyncio.create_task(
        run_health_heartbeat(bus, "agent", interval=0.05),
    )
    try:
        sub = bus.subscribe("system.*.health")
        async with sub:
            event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    assert event.topic == "system.agent.health"
    assert event.type == "health"
    assert event.payload["worker"] == "agent"
    assert isinstance(event.payload["ts"], float)


@pytest.mark.asyncio
async def test_heartbeat_merges_extra_payload(bus: FakeBus) -> None:
    task = asyncio.create_task(
        run_health_heartbeat(
            bus, "forwarder", interval=0.05,
            extra=lambda: {"offset": 4096, "connected": True},
        ),
    )
    try:
        sub = bus.subscribe("system.forwarder.health")
        async with sub:
            event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    assert event.payload["offset"] == 4096
    assert event.payload["connected"] is True
    assert event.payload["worker"] == "forwarder"


@pytest.mark.asyncio
async def test_heartbeat_survives_extra_failure(bus: FakeBus) -> None:
    # An extra() that blows up must not abort the heartbeat loop.
    def _boom():
        raise RuntimeError("extras exploded")

    task = asyncio.create_task(
        run_health_heartbeat(bus, "updater", interval=0.05, extra=_boom),
    )
    try:
        sub = bus.subscribe("system.updater.health")
        async with sub:
            event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    # Base payload still present despite extra() blowing up.
    assert event.payload["worker"] == "updater"


@pytest.mark.asyncio
async def test_heartbeat_is_cancellable_with_none_bus() -> None:
    # Bus-disabled path: loop runs but publishes nothing.  Must still
    # cancel cleanly so lifespan teardown doesn't hang.
    task = asyncio.create_task(
        run_health_heartbeat(None, "agent", interval=0.01),
    )
    await asyncio.sleep(0.05)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert task.done()
