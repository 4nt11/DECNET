"""SSE events stream + list — /api/v1/orchestrator/events{,/stream}."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from decnet.bus import app as _bus_app
from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.web.api import app

_V1 = "/api/v1/orchestrator"


@pytest.fixture
def _fake_app_bus(monkeypatch):
    bus = FakeBus()

    async def _get() -> FakeBus:
        if not bus._connected:
            await bus.connect()
        return bus

    monkeypatch.setattr(_bus_app, "get_app_bus", _get)
    from decnet.web.router.orchestrator import api_events as _ev
    monkeypatch.setattr(_ev, "get_app_bus", _get)
    return bus


@pytest.mark.anyio
async def test_events_unauthenticated_401():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    ) as ac:
        r = await ac.get(f"{_V1}/events")
        assert r.status_code == 401


@pytest.mark.anyio
async def test_stream_unauthenticated_401():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    ) as ac:
        r = await ac.get(f"{_V1}/events/stream")
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_list_returns_paginated_envelope():
    from decnet.web.router.orchestrator.api_list_events import (
        list_orchestrator_events,
    )

    rows = [{"uuid": f"e-{n}", "kind": "traffic"} for n in range(3)]
    with patch(
        "decnet.web.router.orchestrator.api_list_events.repo"
    ) as mock_repo:
        mock_repo.list_orchestrator_events = AsyncMock(return_value=rows)
        mock_repo.count_orchestrator_events = AsyncMock(return_value=3)

        result = await list_orchestrator_events(
            limit=50, offset=0, kind=None,
            user={"uuid": "u", "role": "viewer"},
        )

    assert result == {"total": 3, "limit": 50, "offset": 0, "data": rows}
    mock_repo.list_orchestrator_events.assert_awaited_once_with(
        limit=50, offset=0, kind=None,
    )


@pytest.mark.asyncio
async def test_list_forwards_kind_filter():
    from decnet.web.router.orchestrator.api_list_events import (
        list_orchestrator_events,
    )

    with patch(
        "decnet.web.router.orchestrator.api_list_events.repo"
    ) as mock_repo:
        mock_repo.list_orchestrator_events = AsyncMock(return_value=[])
        mock_repo.count_orchestrator_events = AsyncMock(return_value=0)

        await list_orchestrator_events(
            limit=10, offset=20, kind="file",
            user={"uuid": "u", "role": "viewer"},
        )

    mock_repo.list_orchestrator_events.assert_awaited_once_with(
        limit=10, offset=20, kind="file",
    )
    mock_repo.count_orchestrator_events.assert_awaited_once_with(kind="file")


@pytest.mark.anyio
async def test_stream_emits_snapshot_and_live_events(_fake_app_bus):
    from decnet.web.router.orchestrator import api_events as _ev

    class _FakeRequest:
        async def is_disconnected(self) -> bool:
            return False

    with patch(
        "decnet.web.router.orchestrator.api_events.repo"
    ) as mock_repo:
        mock_repo.list_orchestrator_events = AsyncMock(return_value=[])
        response = await _ev.api_orchestrator_events(
            request=_FakeRequest(),  # type: ignore[arg-type]
            user={"role": "admin", "uuid": "00000000-0000-0000-0000-000000000000"},
        )

    gen = response.body_iterator

    def _as_text(frame) -> str:
        return frame if isinstance(frame, str) else frame.decode()

    async def _publish_after_snapshot() -> None:
        await asyncio.sleep(0.1)
        await _fake_app_bus.publish(
            _topics.orchestrator(_topics.ORCHESTRATOR_TRAFFIC, "decky-1"),
            {"action": "exec:uptime", "success": True},
            event_type=_topics.ORCHESTRATOR_TRAFFIC,
        )
        await asyncio.sleep(0.05)
        await _fake_app_bus.publish(
            _topics.orchestrator(_topics.ORCHESTRATOR_FILE, "decky-1"),
            {"action": "file:create", "success": True},
            event_type=_topics.ORCHESTRATOR_FILE,
        )

    pub_task = asyncio.create_task(_publish_after_snapshot())

    async def _drive():
        saw = {"snapshot": False, "traffic": False, "file": False}
        for _ in range(8):
            frame = _as_text(await gen.__anext__())
            for key in saw:
                if f"event: {key}" in frame:
                    saw[key] = True
            if all(saw.values()):
                break
        return saw

    try:
        seen = await asyncio.wait_for(_drive(), timeout=5.0)
    finally:
        pub_task.cancel()
        try:
            await pub_task
        except (asyncio.CancelledError, Exception):
            pass
        await gen.aclose()

    assert seen["snapshot"]
    assert seen["traffic"]
    assert seen["file"]


def test_sse_name_maps_topic_to_kind():
    from decnet.web.router.orchestrator.api_events import _sse_name_for
    assert _sse_name_for("orchestrator.traffic.decky-1") == "traffic"
    assert _sse_name_for("orchestrator.file.decky-1") == "file"
    assert _sse_name_for("system.bus.health") == "system.bus.health"
