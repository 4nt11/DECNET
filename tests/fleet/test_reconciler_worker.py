# SPDX-License-Identifier: AGPL-3.0-or-later
"""Worker shutdown smoke test for fleet_reconciler_worker.

The reconcile logic itself is exercised in test_reconciler.py.  This file
just verifies the worker's lifecycle wrapper (control listener + heartbeat
+ tick loop) exits cleanly when the bus shutdown signal fires.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from decnet.fleet.reconciler_worker import fleet_reconciler_worker


class _FakeRepo:
    async def list_fleet_deckies(self, *, host_uuid=None):
        return []
    async def upsert_fleet_decky(self, data): pass
    async def delete_fleet_decky(self, **kw): pass
    async def update_fleet_decky_state(self, **kw): pass


@pytest.mark.anyio
async def test_worker_exits_on_shutdown_event(monkeypatch):
    # Patch the bus + control listener so the worker doesn't try to bind
    # to a real socket. The control_task will set `shutdown` once we fire it.
    fake_bus = AsyncMock()
    monkeypatch.setattr(
        "decnet.fleet.reconciler_worker.get_bus",
        lambda **kw: fake_bus,
    )

    captured: dict = {}

    async def _capturing_control_listener(bus, name, shutdown_event):
        captured["shutdown_event"] = shutdown_event
        # Hold the event loop briefly so the worker enters its tick wait,
        # then trigger shutdown.
        await asyncio.sleep(0.05)
        shutdown_event.set()

    async def _noop_heartbeat(bus, name):
        await asyncio.sleep(3600)  # never returns naturally

    monkeypatch.setattr(
        "decnet.fleet.reconciler_worker.run_control_listener",
        _capturing_control_listener,
    )
    monkeypatch.setattr(
        "decnet.fleet.reconciler_worker.run_health_heartbeat",
        _noop_heartbeat,
    )
    # Skip docker observation entirely — we just need the loop to exit.
    monkeypatch.setattr(
        "decnet.fleet.reconciler._real_load_state",
        lambda: None,
    )
    with patch("decnet.fleet.reconciler._collect_container_states",
               return_value=None):
        # interval=10 (long) so we exit via shutdown, not via tick completion
        await asyncio.wait_for(
            fleet_reconciler_worker(_FakeRepo(), interval=10),
            timeout=2.0,
        )
    assert captured["shutdown_event"].is_set()


@pytest.fixture
def anyio_backend():
    return "asyncio"
