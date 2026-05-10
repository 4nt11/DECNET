"""Phase 3 Step 4 — child CRUD: LAN / decky / edge."""
from __future__ import annotations

import pytest

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


async def _seed(name: str = "draft") -> str:
    return await persist(_repo, generate(_cfg(name)))


def _hdr(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── LAN CRUD ──────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_lan_create_ok(client, auth_token):
    topology_id = await _seed("lan-create")
    r = await client.post(
        f"{_V1}/{topology_id}/lans",
        json={"name": "extra-lan"},
        headers=_hdr(auth_token),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "extra-lan"
    assert body["topology_id"] == topology_id
    assert body["subnet"]  # allocator minted one


@pytest.mark.anyio
async def test_lan_create_blocked_when_active(client, auth_token):
    topology_id = await _seed("lan-active")
    await transition_status(_repo, topology_id, TopologyStatus.DEPLOYING)
    await transition_status(_repo, topology_id, TopologyStatus.ACTIVE)

    r = await client.post(
        f"{_V1}/{topology_id}/lans",
        json={"name": "extra-lan"},
        headers=_hdr(auth_token),
    )
    assert r.status_code == 409


@pytest.mark.anyio
async def test_lan_patch_ok(client, auth_token):
    topology_id = await _seed("lan-patch")
    lans = await _repo.list_lans_for_topology(topology_id)
    lan_id = lans[0].id

    r = await client.patch(
        f"{_V1}/{topology_id}/lans/{lan_id}",
        json={"x": 123.0, "y": 456.0},
        headers=_hdr(auth_token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["x"] == 123.0
    assert body["y"] == 456.0


@pytest.mark.anyio
async def test_lan_delete_ok(client, auth_token):
    topology_id = await _seed("lan-delete")
    # Add a throw-away LAN first (deleting the primary LAN would orphan its decky).
    created = await client.post(
        f"{_V1}/{topology_id}/lans",
        json={"name": "disposable"},
        headers=_hdr(auth_token),
    )
    lan_id = created.json()["id"]

    r = await client.delete(
        f"{_V1}/{topology_id}/lans/{lan_id}",
        headers=_hdr(auth_token),
    )
    assert r.status_code == 204


@pytest.mark.anyio
async def test_lan_requires_admin(client, viewer_token):
    topology_id = await _seed("lan-viewer")
    r = await client.post(
        f"{_V1}/{topology_id}/lans",
        json={"name": "nope"},
        headers=_hdr(viewer_token),
    )
    assert r.status_code == 403


# ── Decky CRUD ────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_decky_create_ok(client, auth_token):
    topology_id = await _seed("decky-create")
    r = await client.post(
        f"{_V1}/{topology_id}/deckies",
        json={"name": "test-decky", "services": ["ssh"]},
        headers=_hdr(auth_token),
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["name"] == "test-decky"
    assert body["services"] == ["ssh"]


@pytest.mark.anyio
async def test_decky_patch_ok(client, auth_token):
    topology_id = await _seed("decky-patch")
    deckies = await _repo.list_topology_deckies(topology_id)
    decky_uuid = deckies[0].uuid

    r = await client.patch(
        f"{_V1}/{topology_id}/deckies/{decky_uuid}",
        json={"x": 50.0, "y": 60.0},
        headers=_hdr(auth_token),
    )
    assert r.status_code == 200
    assert r.json()["x"] == 50.0


@pytest.mark.anyio
async def test_decky_delete_ok(client, auth_token):
    topology_id = await _seed("decky-delete")
    created = await client.post(
        f"{_V1}/{topology_id}/deckies",
        json={"name": "transient", "services": []},
        headers=_hdr(auth_token),
    )
    decky_uuid = created.json()["uuid"]

    r = await client.delete(
        f"{_V1}/{topology_id}/deckies/{decky_uuid}",
        headers=_hdr(auth_token),
    )
    assert r.status_code == 204


@pytest.mark.anyio
async def test_decky_delete_missing_404(client, auth_token):
    topology_id = await _seed("decky-missing")
    r = await client.delete(
        f"{_V1}/{topology_id}/deckies/not-a-uuid",
        headers=_hdr(auth_token),
    )
    assert r.status_code == 404


# ── Edge CRUD ─────────────────────────────────────────────────────


@pytest.mark.anyio
async def test_edge_create_and_delete(client, auth_token):
    topology_id = await _seed("edge-crud")
    # Add a second LAN so we can wire an extra edge (bridge) into it.
    new_lan = await client.post(
        f"{_V1}/{topology_id}/lans",
        json={"name": "bridge-target"},
        headers=_hdr(auth_token),
    )
    lan_id = new_lan.json()["id"]

    deckies = await _repo.list_topology_deckies(topology_id)
    decky_uuid = deckies[0].uuid

    r = await client.post(
        f"{_V1}/{topology_id}/edges",
        json={"decky_uuid": decky_uuid, "lan_id": lan_id, "is_bridge": True},
        headers=_hdr(auth_token),
    )
    assert r.status_code == 201, r.text
    edge_id = r.json()["id"]

    r2 = await client.delete(
        f"{_V1}/{topology_id}/edges/{edge_id}",
        headers=_hdr(auth_token),
    )
    assert r2.status_code == 204


@pytest.mark.anyio
async def test_edge_create_bad_refs_400(client, auth_token):
    topology_id = await _seed("edge-bad")
    r = await client.post(
        f"{_V1}/{topology_id}/edges",
        json={"decky_uuid": "ghost", "lan_id": "also-ghost"},
        headers=_hdr(auth_token),
    )
    assert r.status_code == 400


@pytest.mark.anyio
async def test_edge_requires_admin(client, viewer_token):
    topology_id = await _seed("edge-viewer")
    r = await client.post(
        f"{_V1}/{topology_id}/edges",
        json={"decky_uuid": "x", "lan_id": "y"},
        headers=_hdr(viewer_token),
    )
    assert r.status_code == 403
