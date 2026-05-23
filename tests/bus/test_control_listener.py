# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for :func:`run_control_listener`.

The listener is the worker-side half of the Workers panel stop flow:
consume ``system.<worker>.control`` messages, set a shutdown event on a
well-formed ``{"action": "stop"}``, and ignore everything else without
raising.
"""
from __future__ import annotations

import asyncio

import pytest

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.bus.publish import run_control_listener


@pytest.mark.asyncio
async def test_control_listener_sets_shutdown_on_stop() -> None:
    bus = FakeBus()
    await bus.connect()
    shutdown = asyncio.Event()
    try:
        task = asyncio.create_task(run_control_listener(bus, "mutator", shutdown))
        # Give the subscribe() call a tick to register before we publish.
        await asyncio.sleep(0)
        await bus.publish(
            _topics.system_control("mutator"),
            {"action": _topics.WORKER_CONTROL_STOP, "requested_by": "admin"},
            event_type="control",
        )
        await asyncio.wait_for(task, timeout=1.0)
        assert shutdown.is_set()
    finally:
        await bus.close()


@pytest.mark.asyncio
async def test_control_listener_ignores_malformed() -> None:
    bus = FakeBus()
    await bus.connect()
    shutdown = asyncio.Event()
    try:
        task = asyncio.create_task(run_control_listener(bus, "mutator", shutdown))
        await asyncio.sleep(0)
        # Unknown action, non-dict-ish field, missing action — none of
        # these should raise or trigger shutdown.
        await bus.publish(
            _topics.system_control("mutator"),
            {"action": "bogus"}, event_type="control",
        )
        await bus.publish(
            _topics.system_control("mutator"),
            {"requested_by": "admin"}, event_type="control",
        )
        # Now send a real stop to unblock the task so the test terminates.
        await bus.publish(
            _topics.system_control("mutator"),
            {"action": _topics.WORKER_CONTROL_STOP}, event_type="control",
        )
        await asyncio.wait_for(task, timeout=1.0)
        assert shutdown.is_set()
    finally:
        await bus.close()


@pytest.mark.asyncio
async def test_control_listener_none_bus_awaits_shutdown() -> None:
    # With bus=None the listener degrades to awaiting the shutdown event
    # directly — callers can create_task() unconditionally.
    shutdown = asyncio.Event()
    task = asyncio.create_task(run_control_listener(None, "mutator", shutdown))
    await asyncio.sleep(0)
    assert not task.done()
    shutdown.set()
    await asyncio.wait_for(task, timeout=1.0)
