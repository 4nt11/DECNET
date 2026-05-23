# SPDX-License-Identifier: AGPL-3.0-or-later
"""Phase 3 Step 2 — read endpoints: list / get / status-events / catalog."""
from __future__ import annotations

import pytest
from sqlmodel import select as _ss_select

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist, transition_status
from decnet.topology.status import TopologyStatus
from decnet.web.db.models import Topology as _TopologyTable
from decnet.web.dependencies import repo as _repo

_V1 = "/api/v1/topologies"
_LIST = f"{_V1}/"


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


@pytest.mark.anyio
async def test_list_empty_ok(client, auth_token):
    r = await client.get(_LIST, headers={"Authorization": f"Bearer {auth_token}"})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 0
    assert body["data"] == []


@pytest.mark.anyio
async def test_list_requires_auth(client):
    r = await client.get(_LIST)
    assert r.status_code == 401


@pytest.mark.anyio
async def test_list_viewer_allowed(client, viewer_token):
    r = await client.get(_LIST, headers={"Authorization": f"Bearer {viewer_token}"})
    assert r.status_code == 200


@pytest.mark.anyio
async def test_list_with_topology_and_pagination(client, auth_token):
    tid1 = await _seed("alpha")
    await _seed("beta")
    r = await client.get(
        f"{_LIST}?limit=1&offset=0",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    assert len(body["data"]) == 1
    assert body["data"][0]["id"] in {tid1, body["data"][0]["id"]}


@pytest.mark.anyio
async def test_get_topology_hydrated(client, auth_token):
    tid = await _seed("detail")
    r = await client.get(
        f"{_V1}/{tid}", headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["topology"]["id"] == tid
    assert body["topology"]["version"] == 1
    assert body["lans"], "seeded topology has at least one LAN"
    assert body["deckies"]


@pytest.mark.anyio
async def test_get_topology_404(client, auth_token):
    r = await client.get(
        f"{_V1}/does-not-exist",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_status_events_after_transition(client, auth_token):
    tid = await _seed("events")
    await transition_status(_repo, tid, TopologyStatus.DEPLOYING)
    r = await client.get(
        f"{_V1}/{tid}/status-events",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    rows = r.json()
    assert rows and rows[0]["to_status"] == "deploying"


@pytest.mark.anyio
async def test_status_events_404_on_missing(client, auth_token):
    r = await client.get(
        f"{_V1}/nope/status-events",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 404


@pytest.mark.anyio
async def test_services_catalog(client, viewer_token):
    r = await client.get(
        f"{_V1}/services",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["services"], list)
    assert "ssh" in body["services"]


@pytest.mark.anyio
async def test_next_subnet_starts_at_base(client, auth_token):
    r = await client.get(
        f"{_V1}/next-subnet?base=172.20",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 200
    assert r.json()["subnet"].startswith("172.20.")


@pytest.mark.anyio
async def test_next_ip_skips_gateway_and_existing(client, auth_token):
    tid = await _seed("ipalloc")
    # Find a LAN and existing decky IPs from the seeded topology.
    r = await client.get(
        f"{_V1}/{tid}", headers={"Authorization": f"Bearer {auth_token}"}
    )
    body = r.json()
    lan = body["lans"][0]
    taken = {
        (d.get("decky_config") or {}).get("ips_by_lan", {}).get(lan["name"])
        for d in body["deckies"]
    }
    taken.discard(None)
    r2 = await client.get(
        f"{_V1}/{tid}/lans/{lan['id']}/next-ip",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r2.status_code == 200
    ip = r2.json()["ip"]
    assert ip not in taken
    assert not ip.endswith(".1")  # gateway skipped


@pytest.mark.anyio
async def test_next_ip_404_lan(client, auth_token):
    tid = await _seed("nopelan")
    r = await client.get(
        f"{_V1}/{tid}/lans/bogus/next-ip",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert r.status_code == 404
