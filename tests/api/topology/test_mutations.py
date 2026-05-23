# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 3 Step 5 — live mutation queue endpoints."""
from __future__ import annotations

import pytest

from decnet.bus import app as _bus_app
from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist, transition_status
from decnet.topology.status import TopologyStatus
from decnet.web.dependencies import repo as _repo

_V1 = "/api/v1/topologies"


def _cfg(name: str = "draft") -> TopologyConfig:
    return TopologyConfig(
        name=name,
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        services_explicit=["ssh"],
        randomize_services=False,
        seed=0,
    )


async def _seed_active(name: str = "mutation-target") -> str:
    topology_id = await persist(_repo, generate(_cfg(name)))
    await transition_status(_repo, topology_id, TopologyStatus.DEPLOYING)
    await transition_status(_repo, topology_id, TopologyStatus.ACTIVE)
    return topology_id


def _hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── POST /mutations ───────────────────────────────────────────────


@pytest.mark.anyio
async def test_enqueue_ok(client, auth_token):
    topology_id = await _seed_active("enq-ok")
    r = await client.post(
        f"{_V1}/{topology_id}/mutations",
        json={"op": "add_lan", "payload": {"name": "new-lan"}},
        headers=_hdr(auth_token),
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["state"] == "pending"
    assert body["mutation_id"]


@pytest.mark.anyio
async def test_enqueue_blocked_when_pending(client, auth_token):
    topology_id = await persist(_repo, generate(_cfg("enq-pending")))
    # stays in 'pending'
    r = await client.post(
        f"{_V1}/{topology_id}/mutations",
        json={"op": "add_lan", "payload": {"name": "x"}},
        headers=_hdr(auth_token),
    )
    assert r.status_code == 409


@pytest.mark.anyio
async def test_enqueue_unknown_op_rejected(client, auth_token):
    topology_id = await _seed_active("enq-bad-op")
    r = await client.post(
        f"{_V1}/{topology_id}/mutations",
        json={"op": "frobnicate", "payload": {}},
        headers=_hdr(auth_token),
    )
    # Literal-mismatch on MutationEnqueueRequest.op — the project's
    # validation handler leaves these as 422.
    assert r.status_code in (400, 422)


@pytest.mark.anyio
async def test_enqueue_missing_topology_404(client, auth_token):
    r = await client.post(
        f"{_V1}/nope/mutations",
        json={"op": "add_lan", "payload": {}},
        headers=_hdr(auth_token),
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_enqueue_requires_admin(client, viewer_token):
    topology_id = await _seed_active("enq-viewer")
    r = await client.post(
        f"{_V1}/{topology_id}/mutations",
        json={"op": "add_lan", "payload": {"name": "x"}},
        headers=_hdr(viewer_token),
    )
    assert r.status_code == 403


# ── GET /mutations ────────────────────────────────────────────────


@pytest.mark.anyio
async def test_list_empty(client, auth_token):
    topology_id = await _seed_active("list-empty")
    r = await client.get(
        f"{_V1}/{topology_id}/mutations",
        headers=_hdr(auth_token),
    )
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.anyio
async def test_list_after_enqueue(client, auth_token):
    topology_id = await _seed_active("list-after")
    await client.post(
        f"{_V1}/{topology_id}/mutations",
        json={"op": "update_lan", "payload": {"id": "lan-1", "patch": {"x": 10}}},
        headers=_hdr(auth_token),
    )

    r = await client.get(
        f"{_V1}/{topology_id}/mutations",
        headers=_hdr(auth_token),
    )
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 1
    assert rows[0]["op"] == "update_lan"
    assert rows[0]["state"] == "pending"


@pytest.mark.anyio
async def test_list_state_filter(client, auth_token):
    topology_id = await _seed_active("list-filter")
    await client.post(
        f"{_V1}/{topology_id}/mutations",
        json={"op": "add_lan", "payload": {"name": "a"}},
        headers=_hdr(auth_token),
    )
    r = await client.get(
        f"{_V1}/{topology_id}/mutations?state=applied",
        headers=_hdr(auth_token),
    )
    assert r.status_code == 200
    assert r.json() == []  # nothing has been marked applied yet


@pytest.mark.anyio
async def test_list_viewer_ok(client, viewer_token):
    topology_id = await _seed_active("list-viewer")
    r = await client.get(
        f"{_V1}/{topology_id}/mutations",
        headers=_hdr(viewer_token),
    )
    assert r.status_code == 200


# ── Bus publish on enqueue (DEBT-030) ─────────────────────────────


@pytest.fixture
def _fake_app_bus(monkeypatch):
    """Replace the process-wide app bus with an in-process FakeBus."""
    bus = FakeBus()

    async def _get() -> FakeBus:
        if not bus._connected:
            await bus.connect()
        return bus

    monkeypatch.setattr(_bus_app, "get_app_bus", _get)
    # Also patch the re-export in the route module.
    from decnet.web.router.topology import api_mutations as _mod
    monkeypatch.setattr(_mod, "get_app_bus", _get)
    return bus


@pytest.mark.anyio
async def test_enqueue_publishes_on_bus(client, auth_token, _fake_app_bus):
    topology_id = await _seed_active("enq-pub")
    sub = _fake_app_bus.subscribe(
        _topics.topology_mutation(topology_id, _topics.MUTATION_ENQUEUED),
    )
    async with sub:
        r = await client.post(
            f"{_V1}/{topology_id}/mutations",
            json={"op": "add_lan", "payload": {"name": "pub-lan"}},
            headers=_hdr(auth_token),
        )
        assert r.status_code == 202
        mutation_id = r.json()["mutation_id"]
        import asyncio
        event = await asyncio.wait_for(sub.__aiter__().__anext__(), timeout=1.0)
    assert event.type == _topics.MUTATION_ENQUEUED
    assert event.payload["mutation_id"] == mutation_id
    assert event.payload["op"] == "add_lan"
