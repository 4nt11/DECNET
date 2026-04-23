"""Tests for the process-wide app-bus singleton.

Covers the retry-with-backoff behaviour of ``get_app_bus()`` — the
regression guard against the "one-shot veto" bug where a startup race
between ``decnet bus`` and the API's lifespan poisoned the singleton
for the entire process lifetime.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

import decnet.bus.app as app_module


@pytest.fixture(autouse=True)
def _reset_singleton() -> Any:
    """Reset the module-level singleton state between tests."""
    app_module._shared = None
    app_module._last_failure_ts = 0.0
    yield
    app_module._shared = None
    app_module._last_failure_ts = 0.0


@pytest.mark.asyncio
async def test_first_call_succeeds_when_bus_connectable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path: connect succeeds, shared instance returned thereafter."""
    fake_bus = MagicMock()
    fake_bus.connect = AsyncMock()
    monkeypatch.setattr(app_module, "get_bus", lambda **_kw: fake_bus)

    result = await app_module.get_app_bus()
    assert result is fake_bus
    fake_bus.connect.assert_awaited_once()

    # Subsequent call returns cached instance, no second connect.
    result2 = await app_module.get_app_bus()
    assert result2 is fake_bus
    assert fake_bus.connect.await_count == 1


@pytest.mark.asyncio
async def test_connect_failure_backoff_prevents_hot_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After a failed connect, subsequent calls within the backoff
    window return None WITHOUT re-attempting connect — the cost of
    failure stays bounded."""
    fake_bus = MagicMock()
    fake_bus.connect = AsyncMock(side_effect=ConnectionError("socket gone"))
    monkeypatch.setattr(app_module, "get_bus", lambda **_kw: fake_bus)

    assert await app_module.get_app_bus() is None
    assert fake_bus.connect.await_count == 1

    # Second immediate call: still within backoff, no retry.
    assert await app_module.get_app_bus() is None
    assert fake_bus.connect.await_count == 1

    # Third immediate call: same thing.
    assert await app_module.get_app_bus() is None
    assert fake_bus.connect.await_count == 1


@pytest.mark.asyncio
async def test_connect_retried_after_backoff_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once the backoff window expires, the next call tries connect()
    again. This is the regression guard for the original 'one-shot veto'
    bug — the whole point of the fix."""
    fake_bus = MagicMock()
    # First attempt fails, second succeeds.
    fake_bus.connect = AsyncMock(
        side_effect=[ConnectionError("socket gone"), None]
    )
    monkeypatch.setattr(app_module, "get_bus", lambda **_kw: fake_bus)

    assert await app_module.get_app_bus() is None
    assert fake_bus.connect.await_count == 1

    # Simulate the backoff window elapsing by rewinding the recorded
    # failure timestamp into the past.
    app_module._last_failure_ts = time.monotonic() - (app_module._RETRY_BACKOFF + 0.1)

    result = await app_module.get_app_bus()
    assert result is fake_bus
    assert fake_bus.connect.await_count == 2


@pytest.mark.asyncio
async def test_close_app_bus_clears_backoff_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """close_app_bus() after a failure (or after a successful bus) must
    reset _last_failure_ts so the next get_app_bus() retries immediately
    — otherwise tests that bring the app-bus up/down/up in one process
    would see stale backoff."""
    fake_bus = MagicMock()
    fake_bus.connect = AsyncMock(side_effect=ConnectionError("x"))
    fake_bus.close = AsyncMock()
    monkeypatch.setattr(app_module, "get_bus", lambda **_kw: fake_bus)

    assert await app_module.get_app_bus() is None
    assert app_module._last_failure_ts > 0.0

    await app_module.close_app_bus()
    assert app_module._last_failure_ts == 0.0
    # Next call retries immediately (no backoff wait).
    fake_bus.connect.side_effect = None  # make it succeed this time
    assert await app_module.get_app_bus() is fake_bus


@pytest.mark.asyncio
async def test_concurrent_callers_do_not_stampede_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lock must serialise concurrent callers so a just-started bus
    doesn't get hammered with N parallel connect attempts."""
    fake_bus = MagicMock()
    fake_bus.connect = AsyncMock()
    monkeypatch.setattr(app_module, "get_bus", lambda **_kw: fake_bus)

    results = await asyncio.gather(
        *[app_module.get_app_bus() for _ in range(10)]
    )
    assert all(r is fake_bus for r in results)
    assert fake_bus.connect.await_count == 1
