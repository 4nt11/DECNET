"""SSE events stream — GET /api/v1/campaigns/events.

Mirror of :mod:`tests.api.identities.test_events_stream`. Drives the
generator directly to dodge the full httpx streaming roundtrip.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from decnet.bus import app as _bus_app
from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.web.api import app

_V1 = "/api/v1/campaigns"


@pytest.fixture
def _fake_app_bus(monkeypatch):
    bus = FakeBus()

    async def _get() -> FakeBus:
        if not bus._connected:
            await bus.connect()
        return bus

    monkeypatch.setattr(_bus_app, "get_app_bus", _get)
    from decnet.web.router.campaigns import api_events as _ev
    monkeypatch.setattr(_ev, "get_app_bus", _get)
    return bus


@pytest.mark.anyio
async def test_campaign_events_unauthenticated_401():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    ) as ac:
        r = await ac.get(f"{_V1}/events")
        assert r.status_code == 401


@pytest.mark.anyio
async def test_campaign_events_emits_snapshot_and_live_event(_fake_app_bus):
    """Snapshot on connect + live forwarding under ``campaign.>``."""
    from decnet.web.router.campaigns import api_events as _ev

    class _FakeRequest:
        async def is_disconnected(self) -> bool:
            return False

    response = await _ev.api_campaigns_events(
        request=_FakeRequest(),  # type: ignore[arg-type]
        user={"role": "admin", "uuid": "00000000-0000-0000-0000-000000000000"},
    )
    gen = response.body_iterator

    def _as_text(frame) -> str:
        return frame if isinstance(frame, str) else frame.decode()

    async def _publish_after_snapshot() -> None:
        await asyncio.sleep(0.1)
        await _fake_app_bus.publish(
            _topics.campaign(_topics.CAMPAIGN_FORMED),
            {"campaign_uuid": "c-1", "identity_uuids": ["i-1"]},
            event_type=_topics.CAMPAIGN_FORMED,
        )
        await asyncio.sleep(0.05)
        await _fake_app_bus.publish(
            _topics.campaign(_topics.CAMPAIGN_IDENTITY_ASSIGNED),
            {"campaign_uuid": "c-1", "identity_uuid": "i-2"},
            event_type=_topics.CAMPAIGN_IDENTITY_ASSIGNED,
        )

    pub_task = asyncio.create_task(_publish_after_snapshot())

    async def _drive():
        saw = {"snapshot": False, "formed": False, "identity.assigned": False}
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
    assert seen["formed"]
    assert seen["identity.assigned"]


def test_sse_name_maps_dotted_leaves():
    from decnet.web.router.campaigns.api_events import _sse_name_for
    assert _sse_name_for("campaign.formed") == "formed"
    assert _sse_name_for("campaign.identity.assigned") == "identity.assigned"
    assert _sse_name_for("campaign.merged") == "merged"
    assert _sse_name_for("campaign.unmerged") == "unmerged"
    assert _sse_name_for("system.bus.health") == "system.bus.health"
