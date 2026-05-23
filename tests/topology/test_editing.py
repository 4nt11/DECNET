# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pre-deploy mutation repo methods: pending-only, version-aware."""
from __future__ import annotations

import pytest

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist, transition_status
from decnet.topology.status import TopologyNotEditable, TopologyStatus
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="edit",
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=2,
        deckies_per_lan_max=2,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=6,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "edit.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_add_lan_to_pending_bumps_version(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    await repo.add_lan(
        {"topology_id": tid, "name": "LAN-NEW", "subnet": "10.55.0.0/24", "is_dmz": False},
        expected_version=1,
    )
    topo = await repo.get_topology(tid)
    assert topo.version == 2
    lans = {l.name for l in await repo.list_lans_for_topology(tid)}
    assert "LAN-NEW" in lans


@pytest.mark.anyio
async def test_update_decky_roundtrips_service_config(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    decky = (await repo.list_topology_deckies(tid))[0]
    patch = dict(decky.decky_config)
    patch["service_config"] = {"ssh": {"password": "megapassword"}}
    await repo.update_topology_decky(
        decky.uuid, {"decky_config": patch}, expected_version=1,
    )
    fresh = next(
        d for d in await repo.list_topology_deckies(tid)
        if d.uuid == decky.uuid
    )
    assert fresh.decky_config["service_config"]["ssh"]["password"] == "megapassword"


@pytest.mark.anyio
async def test_update_decky_rejected_on_active_topology(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    decky = (await repo.list_topology_deckies(tid))[0]
    # pending → deploying → active
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(repo, tid, TopologyStatus.ACTIVE)
    with pytest.raises(TopologyNotEditable) as ei:
        await repo.update_topology_decky(
            decky.uuid,
            {"decky_config": decky.decky_config},
            enforce_pending=True,
        )
    assert ei.value.status == TopologyStatus.ACTIVE


@pytest.mark.anyio
async def test_delete_lan_with_home_decky_refused(repo):
    """A LAN whose decky has no other edge cannot be deleted — it'd orphan."""
    plan = generate(_cfg(depth=1, branching_factor=1, deckies_per_lan_max=1, deckies_per_lan_min=1))
    tid = await persist(repo, plan)
    lan = (await repo.list_lans_for_topology(tid))[0]
    with pytest.raises(ValueError, match="orphaned"):
        await repo.delete_lan(lan.id)


@pytest.mark.anyio
async def test_delete_edge_leaves_decky_intact(repo):
    """Deleting one bridge edge of a multi-homed decky should succeed."""
    # depth=1 branching=1 gives DMZ(LAN-00) + LAN-01 with a bridge decky.
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    edges = await repo.list_topology_edges(tid)
    bridge_edges = [e for e in edges if e.is_bridge]
    assert bridge_edges, "generator should produce at least one bridge edge"
    # Delete exactly one — the bridge decky should keep at least one edge.
    edge = bridge_edges[0]
    before_deckies = {d.uuid for d in await repo.list_topology_deckies(tid)}
    await repo.delete_topology_edge(edge.id)
    after_deckies = {d.uuid for d in await repo.list_topology_deckies(tid)}
    assert before_deckies == after_deckies
    remaining = await repo.list_topology_edges(tid)
    assert edge.id not in {e.id for e in remaining}


@pytest.mark.anyio
async def test_delete_decky_cascades_edges(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    decky = (await repo.list_topology_deckies(tid))[0]
    await repo.delete_topology_decky(decky.uuid)
    # No edge pointing to the removed decky remains.
    remaining = await repo.list_topology_edges(tid)
    assert decky.uuid not in {e.decky_uuid for e in remaining}


@pytest.mark.anyio
async def test_delete_edge_rejected_on_active(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    edges = await repo.list_topology_edges(tid)
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(repo, tid, TopologyStatus.ACTIVE)
    with pytest.raises(TopologyNotEditable):
        await repo.delete_topology_edge(edges[0].id)
