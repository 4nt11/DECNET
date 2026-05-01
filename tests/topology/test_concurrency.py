"""Optimistic-concurrency (version) checks on topology child mutations."""
from __future__ import annotations

import pytest

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist
from decnet.topology.status import VersionConflict
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="ver",
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=2,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "ver.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_version_starts_at_one_after_persist(repo):
    plan = generate(_cfg())
    # persist() adds LANs/deckies/edges without expected_version, so
    # the version token stays at 1.
    tid = await persist(repo, plan)
    topo = await repo.get_topology(tid)
    assert topo.version == 1


@pytest.mark.anyio
async def test_happy_path_two_sequential_writes(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)

    await repo.add_lan(
        {"topology_id": tid, "name": "LAN-A", "subnet": "10.9.0.0/24", "is_dmz": False},
        expected_version=1,
    )
    assert (await repo.get_topology(tid)).version == 2

    await repo.add_lan(
        {"topology_id": tid, "name": "LAN-B", "subnet": "10.9.1.0/24", "is_dmz": False},
        expected_version=2,
    )
    assert (await repo.get_topology(tid)).version == 3


@pytest.mark.anyio
async def test_stale_expected_version_raises(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)

    await repo.add_lan(
        {"topology_id": tid, "name": "LAN-A", "subnet": "10.8.0.0/24", "is_dmz": False},
        expected_version=1,
    )
    with pytest.raises(VersionConflict) as ei:
        await repo.add_lan(
            {"topology_id": tid, "name": "LAN-B", "subnet": "10.8.1.0/24", "is_dmz": False},
            expected_version=1,  # stale
        )
    assert ei.value.current == 2
    assert ei.value.expected == 1


@pytest.mark.anyio
async def test_no_expected_version_skips_check(repo):
    """Existing callers (persist) don't pass expected_version and must
    continue to work without version bumps."""
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    before = (await repo.get_topology(tid)).version
    await repo.add_lan(
        {"topology_id": tid, "name": "LAN-X", "subnet": "10.7.0.0/24", "is_dmz": False}
    )
    after = (await repo.get_topology(tid)).version
    assert before == after  # no bump when version not asserted


@pytest.mark.anyio
async def test_update_topology_decky_bumps_version(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    decky = (await repo.list_topology_deckies(tid))[0]
    await repo.update_topology_decky(
        decky.uuid,
        {"decky_config": {"name": decky.name, "services": ["ssh"],
                          "ips_by_lan": decky.decky_config["ips_by_lan"],
                          "forwards_l3": False,
                          "service_config": {"ssh": {"password": "x"}}}},
        expected_version=1,
    )
    assert (await repo.get_topology(tid)).version == 2


@pytest.mark.anyio
async def test_update_lan_bumps_version(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    lan = (await repo.list_lans_for_topology(tid))[0]
    await repo.update_lan(lan.id, {"name": "LAN-RENAMED"}, expected_version=1)
    assert (await repo.get_topology(tid)).version == 2
