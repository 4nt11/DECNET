"""Tests for the Workers panel API endpoints.

Covers ``GET /api/v1/workers`` (viewer-readable, always surfaces every
known worker) and ``POST /api/v1/workers/{name}/stop`` (admin-only,
publishes a stop intent on the bus).
"""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.web import worker_registry as _wr
from decnet.web.router.workers import api_control_worker as _ctl
from decnet.web.router.workers import api_list_workers as _list
from decnet.web.worker_registry import KNOWN_WORKERS


@pytest.fixture(autouse=True)
def _reset_registry() -> None:
    _wr.reset_registry_for_tests()
    yield
    _wr.reset_registry_for_tests()


@pytest.fixture
async def fake_bus(monkeypatch) -> FakeBus:
    bus = FakeBus()
    await bus.connect()

    async def _stub_get_app_bus() -> FakeBus:
        return bus

    # Patch the symbol the control endpoint imported into its namespace.
    monkeypatch.setattr(_ctl, "get_app_bus", _stub_get_app_bus)
    yield bus
    await bus.close()


@pytest.mark.asyncio
async def test_list_workers_viewer_sees_all_unknown(
    client: httpx.AsyncClient, viewer_token: str,
) -> None:
    resp = await client.get(
        "/api/v1/workers",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    names = {w["name"] for w in body["workers"]}
    assert names == set(KNOWN_WORKERS)
    # No heartbeats have arrived in the test harness, so every row is unknown.
    for w in body["workers"]:
        assert w["status"] == "unknown"
        assert w["last_heartbeat_ts"] is None
        assert w["seconds_since"] is None
    assert "bus_connected" in body
    assert isinstance(body["bus_connected"], bool)
    # `installed` flag is always present + boolean.
    for w in body["workers"]:
        assert "installed" in w
        assert isinstance(w["installed"], bool)


@pytest.mark.asyncio
async def test_list_workers_requires_auth(client: httpx.AsyncClient) -> None:
    resp = await client.get("/api/v1/workers")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_workers_reports_bus_connected_false_when_no_bus(
    client: httpx.AsyncClient, viewer_token: str, monkeypatch,
) -> None:
    async def _no_bus() -> None:
        return None

    monkeypatch.setattr(_list, "get_app_bus", _no_bus)
    resp = await client.get(
        "/api/v1/workers",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["bus_connected"] is False


@pytest.mark.asyncio
async def test_list_workers_reports_bus_connected_true_with_fake_bus(
    client: httpx.AsyncClient, viewer_token: str, monkeypatch,
) -> None:
    bus = FakeBus()
    await bus.connect()

    async def _fake_bus() -> FakeBus:
        return bus

    monkeypatch.setattr(_list, "get_app_bus", _fake_bus)
    try:
        resp = await client.get(
            "/api/v1/workers",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["bus_connected"] is True
    finally:
        await bus.close()


@pytest.mark.asyncio
async def test_stop_worker_admin_publishes_on_bus(
    client: httpx.AsyncClient, auth_token: str, fake_bus: FakeBus,
) -> None:
    topic = _topics.system_control("mutator")
    received: list[Any] = []

    sub = fake_bus.subscribe(topic)
    await sub.__aenter__()

    async def _drain() -> None:
        async for event in sub:
            received.append(event)
            return

    import asyncio
    reader = asyncio.create_task(_drain())
    # Give the subscribe a tick so the publish lands on a live reader.
    await asyncio.sleep(0)

    try:
        resp = await client.post(
            "/api/v1/workers/mutator/stop",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert resp.status_code == 202
        body = resp.json()
        assert body == {"accepted": True, "worker": "mutator", "action": "stop"}

        await asyncio.wait_for(reader, timeout=1.0)
        assert len(received) == 1
        ev = received[0]
        assert ev.topic == topic
        assert ev.payload["action"] == _topics.WORKER_CONTROL_STOP
        assert "requested_by" in ev.payload
        assert "ts" in ev.payload
    finally:
        await sub.__aexit__(None, None, None)


@pytest.mark.asyncio
async def test_stop_worker_viewer_forbidden(
    client: httpx.AsyncClient, viewer_token: str, fake_bus: FakeBus,
) -> None:
    resp = await client.post(
        "/api/v1/workers/mutator/stop",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_stop_worker_unknown_name_404(
    client: httpx.AsyncClient, auth_token: str, fake_bus: FakeBus,
) -> None:
    resp = await client.post(
        "/api/v1/workers/nonsense/stop",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 404
