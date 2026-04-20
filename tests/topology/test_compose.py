"""MazeNET compose-generator + teardown-order tests."""
from __future__ import annotations

import pytest

from decnet.engine.deployer import _teardown_order
from decnet.topology.compose import (
    _container_name,
    _network_name,
    generate_topology_compose,
)
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import hydrate, persist
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="cmp",
        depth=2,
        branching_factor=2,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=9,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "compose.db"))
    await r.initialize()
    return r


@pytest.mark.anyio
async def test_compose_has_one_network_per_lan(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    hydrated = await hydrate(repo, tid)

    data = generate_topology_compose(hydrated)
    assert set(data["networks"].keys()) == {
        _network_name(tid, lan.name) for lan in plan.lans
    }
    for net in data["networks"].values():
        assert net["external"] is True


@pytest.mark.anyio
async def test_compose_multi_home_bridge_decky(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    hydrated = await hydrate(repo, tid)
    data = generate_topology_compose(hydrated)

    # Every bridge decky (multi-homed) must list ≥2 networks in its base.
    for decky in hydrated["deckies"]:
        cfg = decky["decky_config"]
        base = data["services"][cfg["name"]]
        assert base["container_name"] == _container_name(tid, cfg["name"])
        assert len(base["networks"]) == len(cfg["ips_by_lan"])
        for lan_name, ip in cfg["ips_by_lan"].items():
            net_key = _network_name(tid, lan_name)
            assert base["networks"][net_key]["ipv4_address"] == ip


@pytest.mark.anyio
async def test_compose_forwards_l3_sets_sysctl(repo):
    # Force every bridge to forward L3, then assert at least one base has it.
    plan = generate(_cfg(bridge_forward_probability=1.0))
    tid = await persist(repo, plan)
    hydrated = await hydrate(repo, tid)
    data = generate_topology_compose(hydrated)

    forwarders = [
        d for d in hydrated["deckies"]
        if d["decky_config"].get("forwards_l3")
    ]
    assert forwarders, "expected at least one forwarding bridge decky"
    for d in forwarders:
        base = data["services"][d["decky_config"]["name"]]
        assert base["sysctls"]["net.ipv4.ip_forward"] == 1
        assert "NET_ADMIN" in base["cap_add"]


def test_teardown_order_is_leaf_first():
    lans = [
        {"name": "LAN-00"},
        {"name": "LAN-01"},
        {"name": "LAN-02"},
        {"name": "LAN-03"},
    ]
    order = _teardown_order(lans)
    assert order == ["LAN-03", "LAN-02", "LAN-01", "LAN-00"]
    # DMZ is last — nothing should be torn down after LAN-00.
    assert order[-1] == "LAN-00"
