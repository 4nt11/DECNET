# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for graceful publish-on-closed-bus behaviour.

Regression guard for the 'publish on closed bus' log flood: when a
worker's private bus closes (shutdown) but stream threads keep calling
the publish closure, the bus must not raise a RuntimeError per call.
First drop warns loudly (bus is critical infra); subsequent drops on
the same instance are DEBUG to prevent the flood.
"""
from __future__ import annotations

import asyncio
import logging
import pathlib
from unittest.mock import MagicMock

import pytest

from decnet.bus.publish import make_thread_safe_publisher
from decnet.bus.unix_client import UnixSocketBus


def _make_closed_bus() -> UnixSocketBus:
    """Build a UnixSocketBus and flip _closed without touching sockets.

    We don't need a live connection to test the closed-publish path —
    the guard clause short-circuits before any I/O.
    """
    bus = UnixSocketBus(pathlib.Path("/tmp/does-not-matter.sock"))
    bus._closed = True
    return bus


@pytest.mark.asyncio
async def test_publish_on_closed_bus_returns_silently(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """First post-close publish warns loudly; does not raise."""
    bus = _make_closed_bus()
    with caplog.at_level(logging.WARNING, logger="decnet.bus.client"):
        await bus.publish("system.log", {"x": 1})

    assert any(
        rec.levelno == logging.WARNING
        and "publish on closed bus dropped" in rec.getMessage()
        for rec in caplog.records
    ), f"expected one WARNING, got: {[(r.levelname, r.getMessage()) for r in caplog.records]}"


@pytest.mark.asyncio
async def test_subsequent_closed_publishes_downgrade_to_debug(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Only the first drop warns; the next N drops are DEBUG. This is
    the regression guard against the log flood."""
    bus = _make_closed_bus()

    with caplog.at_level(logging.DEBUG, logger="decnet.bus.client"):
        for _ in range(50):
            await bus.publish("system.log", {"x": 1})

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    debugs = [r for r in caplog.records if r.levelno == logging.DEBUG]
    assert len(warnings) == 1, (
        f"expected exactly 1 WARNING across 50 publishes, got {len(warnings)}"
    )
    assert len(debugs) >= 49, (
        f"expected >=49 DEBUG drops, got {len(debugs)}"
    )


@pytest.mark.asyncio
async def test_thread_safe_publisher_short_circuits_on_closed_bus() -> None:
    """The sync shim returned by make_thread_safe_publisher must NOT
    marshal a coroutine onto the loop when the bus is already closed."""
    bus = _make_closed_bus()
    loop = asyncio.get_running_loop()

    publisher = make_thread_safe_publisher(bus, loop)

    # Patch run_coroutine_threadsafe so we can detect if the shim tries
    # to marshal anything.
    import decnet.bus.publish as pub_mod
    called = MagicMock()
    orig = asyncio.run_coroutine_threadsafe
    pub_mod.asyncio.run_coroutine_threadsafe = lambda coro, _loop: (called(), orig(coro, _loop))[1]

    try:
        publisher("system.log", {"x": 1})
        publisher("system.log", {"x": 2})
        publisher("system.log", {"x": 3})
    finally:
        pub_mod.asyncio.run_coroutine_threadsafe = orig

    called.assert_not_called()


@pytest.mark.asyncio
async def test_thread_safe_publisher_noop_when_bus_is_none() -> None:
    """A None bus still yields a no-op callable (pre-existing contract)."""
    loop = asyncio.get_running_loop()
    publisher = make_thread_safe_publisher(None, loop)
    # Should not raise, return None.
    assert publisher("topic", {"x": 1}) is None
