"""SSE events stream — GET /topologies/{id}/events (DEBT-030)."""
from __future__ import annotations

import asyncio

import httpx
import pytest

from decnet.bus import app as _bus_app
from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist, transition_status
from decnet.topology.status import TopologyStatus
from decnet.web.api import app
from decnet.web.dependencies import repo as _repo

_V1 = "/api/v1/topologies"


def _cfg(name: str) -> TopologyConfig:
    return TopologyConfig(
        name=name, depth=1, branching_factor=1,
        deckies_per_lan_min=1, deckies_per_lan_max=1,
        services_explicit=["ssh"], randomize_services=False, seed=0,
    )


async def _seed_active(name: str) -> str:
    tid = await persist(_repo, generate(_cfg(name)))
    await transition_status(_repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(_repo, tid, TopologyStatus.ACTIVE)
    return tid


@pytest.fixture
def _fake_app_bus(monkeypatch):
    bus = FakeBus()

    async def _get() -> FakeBus:
        if not bus._connected:
            await bus.connect()
        return bus

    monkeypatch.setattr(_bus_app, "get_app_bus", _get)
    from decnet.web.router.topology import api_events as _ev
    from decnet.web.router.topology import api_mutations as _mu
    monkeypatch.setattr(_ev, "get_app_bus", _get)
    monkeypatch.setattr(_mu, "get_app_bus", _get)
    return bus


@pytest.mark.anyio
async def test_events_unauthenticated_401():
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    ) as ac:
        r = await ac.get(f"{_V1}/any/events")
        assert r.status_code == 401


@pytest.mark.anyio
async def test_events_missing_topology_404(auth_token, _fake_app_bus):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test",
    ) as ac:
        r = await ac.get(
            f"{_V1}/nope/events",
            params={"token": auth_token},
        )
        assert r.status_code == 404


@pytest.mark.anyio
async def test_events_emits_snapshot_and_live_event(auth_token, _fake_app_bus):
    """Drive the generator directly — avoids the full httpx streaming
    roundtrip, which is painful under ASGITransport + an infinite SSE loop.

    The route is thin glue: if the generator yields snapshot + mapped
    bus events, the handler works.  Auth/404 paths are covered above.
    """
    from decnet.web.router.topology import api_events as _ev

    tid = await _seed_active("evt-live")

    class _FakeRequest:
        async def is_disconnected(self) -> bool:
            return False

    # Patch out the role gate so we can call the async endpoint directly.
    response = await _ev.api_topology_events(
        topology_id=tid,
        request=_FakeRequest(),  # type: ignore[arg-type]
        user={"role": "admin", "uuid": "00000000-0000-0000-0000-000000000000"},
    )
    gen = response.body_iterator

    def _as_text(frame) -> str:
        return frame if isinstance(frame, str) else frame.decode()

    async def _publish_after_snapshot() -> None:
        # Wait for the generator to reach its blocking subscribe state.
        # We don't have a synchronization primitive, so a short sleep is
        # good enough — the test-level timeout catches any real hang.
        await asyncio.sleep(0.1)
        await _fake_app_bus.publish(
            _topics.topology_mutation(tid, _topics.MUTATION_APPLIED),
            {"mutation_id": "m1", "op": "add_lan"},
            event_type=_topics.MUTATION_APPLIED,
        )

    pub_task = asyncio.create_task(_publish_after_snapshot())

    async def _drive() -> tuple[bool, bool]:
        saw_snapshot = False
        saw_live = False
        # Bounded — real loop produces keepalive, snapshot, (waits), then
        # forwarded event.  Max 5 iterations covers pathological orderings.
        for _ in range(5):
            frame = _as_text(await gen.__anext__())
            if "event: snapshot" in frame:
                saw_snapshot = True
            if "event: mutation.applied" in frame:
                saw_live = True
                break
        return saw_snapshot, saw_live

    try:
        saw_snapshot, saw_live = await asyncio.wait_for(_drive(), timeout=5.0)
    finally:
        pub_task.cancel()
        try:
            await pub_task
        except (asyncio.CancelledError, Exception):
            pass
        await gen.aclose()

    assert saw_snapshot
    assert saw_live
