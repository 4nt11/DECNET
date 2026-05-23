# SPDX-License-Identifier: AGPL-3.0-or-later
"""SSE events stream — GET /api/v1/identities/events.

Mirrors :mod:`tests.api.topology.test_events_stream` — the route is
thin glue, so we drive the generator directly to dodge the full
httpx streaming roundtrip under ASGITransport.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from decnet.bus import app as _bus_app
from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.web.api import app

_V1 = "/api/v1/identities"


@pytest.fixture
def _fake_app_bus(monkeypatch):
    bus = FakeBus()

    async def _get() -> FakeBus:
        if not bus._connected:
            await bus.connect()
        return bus

    monkeypatch.setattr(_bus_app, "get_app_bus", _get)
    from decnet.web.router.identities import api_events as _ev
    monkeypatch.setattr(_ev, "get_app_bus", _get)
    return bus


@pytest.mark.anyio
async def test_identity_events_unauthenticated_401():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    ) as ac:
        r = await ac.get(f"{_V1}/events")
        assert r.status_code == 401


@pytest.mark.anyio
async def test_identity_events_emits_snapshot_and_live_event(_fake_app_bus):
    """Generator yields a snapshot frame on connect, then forwards
    bus events under ``identity.>`` as named SSE events."""
    from decnet.web.router.identities import api_events as _ev

    class _FakeRequest:
        async def is_disconnected(self) -> bool:
            return False

    response = await _ev.api_identities_events(
        request=_FakeRequest(),  # type: ignore[arg-type]
        user={"role": "admin", "uuid": "00000000-0000-0000-0000-000000000000"},
    )
    gen = response.body_iterator

    def _as_text(frame) -> str:
        return frame if isinstance(frame, str) else frame.decode()

    async def _publish_after_snapshot() -> None:
        await asyncio.sleep(0.1)
        await _fake_app_bus.publish(
            _topics.identity(_topics.IDENTITY_FORMED),
            {
                "identity_uuid": "id-1",
                "observation_uuids": ["obs-1", "obs-2"],
            },
            event_type=_topics.IDENTITY_FORMED,
        )
        await asyncio.sleep(0.05)
        await _fake_app_bus.publish(
            _topics.identity(_topics.IDENTITY_UNMERGED),
            {"resurrected_uuid": "id-2", "former_winner_uuid": "id-1"},
            event_type=_topics.IDENTITY_UNMERGED,
        )

    pub_task = asyncio.create_task(_publish_after_snapshot())

    async def _drive() -> tuple[bool, bool, bool]:
        saw_snapshot = False
        saw_formed = False
        saw_unmerged = False
        for _ in range(8):
            frame = _as_text(await gen.__anext__())
            if "event: snapshot" in frame:
                saw_snapshot = True
            if "event: formed" in frame:
                saw_formed = True
            if "event: unmerged" in frame:
                saw_unmerged = True
            if saw_snapshot and saw_formed and saw_unmerged:
                break
        return saw_snapshot, saw_formed, saw_unmerged

    try:
        saw_snapshot, saw_formed, saw_unmerged = await asyncio.wait_for(
            _drive(), timeout=5.0,
        )
    finally:
        pub_task.cancel()
        try:
            await pub_task
        except (asyncio.CancelledError, Exception):
            pass
        await gen.aclose()

    assert saw_snapshot
    assert saw_formed
    assert saw_unmerged


def test_sse_name_maps_dotted_leaves():
    """``observation.linked`` survives the topic-to-event-name mapping
    intact so the frontend can switch on the full dotted leaf."""
    from decnet.web.router.identities.api_events import _sse_name_for
    assert _sse_name_for("identity.formed") == "formed"
    assert _sse_name_for("identity.observation.linked") == "observation.linked"
    assert _sse_name_for("identity.merged") == "merged"
    assert _sse_name_for("identity.unmerged") == "unmerged"
    # Non-identity topics pass through unchanged.
    assert _sse_name_for("system.bus.health") == "system.bus.health"
