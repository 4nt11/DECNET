"""Validator-rule unit tests + deployer precondition integration."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from decnet.engine.deployer import deploy_topology
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import hydrate, persist
from decnet.topology.status import TopologyStatus
from decnet.topology.validate import (
    ValidationError,
    errors,
    validate,
)
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="val",
        depth=1,
        branching_factor=1,
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
    r = get_repository(db_path=str(tmp_path / "val.db"))
    await r.initialize()
    return r


async def _hydrate_plan(repo, plan) -> dict:
    tid = await persist(repo, plan)
    return await hydrate(repo, tid), tid


# --------------------------------------------------------------------- rules


@pytest.mark.anyio
async def test_valid_topology_has_no_errors(repo):
    plan = generate(_cfg())
    h, _ = await _hydrate_plan(repo, plan)
    assert errors(validate(h)) == []


@pytest.mark.anyio
async def test_dmz_missing(repo):
    plan = generate(_cfg())
    h, _ = await _hydrate_plan(repo, plan)
    for lan in h["lans"]:
        lan["is_dmz"] = False
    codes = [i.code for i in validate(h) if i.severity == "error"]
    # DMZ_MISSING plus cascaded DMZ_ORPHAN checks are both acceptable;
    # the specific rule must fire at minimum.
    assert "DMZ_MISSING" in codes


@pytest.mark.anyio
async def test_dmz_multiple(repo):
    plan = generate(_cfg())
    h, _ = await _hydrate_plan(repo, plan)
    for lan in h["lans"]:
        lan["is_dmz"] = True
    assert "DMZ_MULTIPLE" in [i.code for i in validate(h)]


@pytest.mark.anyio
async def test_orphan_decky(repo):
    plan = generate(_cfg())
    h, _ = await _hydrate_plan(repo, plan)
    h["edges"] = [e for e in h["edges"] if e["decky_uuid"] != h["deckies"][0]["uuid"]]
    assert "DECKY_ORPHAN" in [i.code for i in validate(h)]


@pytest.mark.anyio
async def test_ip_collision(repo):
    plan = generate(_cfg(deckies_per_lan_max=2, deckies_per_lan_min=2))
    h, _ = await _hydrate_plan(repo, plan)
    # Force two deckies in the same LAN to claim the same IP.
    deckies = [
        d for d in h["deckies"]
        if any(
            e["decky_uuid"] == d["uuid"]
            for e in h["edges"]
            if e["lan_id"] == h["lans"][0]["id"]
        )
    ]
    assert len(deckies) >= 2
    shared_ip = next(iter(deckies[0]["decky_config"]["ips_by_lan"].values()))
    deckies[1]["decky_config"]["ips_by_lan"][h["lans"][0]["name"]] = shared_ip
    assert "IP_COLLISION" in [i.code for i in validate(h)]


@pytest.mark.anyio
async def test_ip_out_of_subnet(repo):
    plan = generate(_cfg())
    h, _ = await _hydrate_plan(repo, plan)
    d = h["deckies"][0]
    lan_name = next(iter(d["decky_config"]["ips_by_lan"]))
    d["decky_config"]["ips_by_lan"][lan_name] = "10.99.99.99"
    assert "IP_OUT_OF_SUBNET" in [i.code for i in validate(h)]


@pytest.mark.anyio
async def test_subnet_overlap(repo):
    plan = generate(_cfg())
    h, _ = await _hydrate_plan(repo, plan)
    # Shrink two LANs onto overlapping /16s.
    h["lans"][0]["subnet"] = "10.0.0.0/16"
    if len(h["lans"]) > 1:
        h["lans"][1]["subnet"] = "10.0.5.0/24"
        codes = [i.code for i in validate(h)]
        assert "SUBNET_OVERLAP" in codes


@pytest.mark.anyio
async def test_unknown_service(repo):
    plan = generate(_cfg())
    h, _ = await _hydrate_plan(repo, plan)
    h["deckies"][0]["services"].append("teleporter-xyz")
    assert "UNKNOWN_SERVICE" in [i.code for i in validate(h)]


@pytest.mark.anyio
async def test_service_config_undeclared(repo):
    plan = generate(_cfg())
    h, _ = await _hydrate_plan(repo, plan)
    h["deckies"][0]["decky_config"]["service_config"] = {
        "rdp": {"password": "no"}
    }
    # "rdp" is not in the decky's services list (which is ["ssh"]).
    assert "SERVICE_CFG_UNDECLARED" in [i.code for i in validate(h)]


# --------------------------------------------------------------------- per-LAN host

@pytest.mark.anyio
async def test_bridge_decky_same_host_passes_when_colocated(repo):
    """A bridge decky whose LANs share a host must not flag."""
    plan = generate(
        _cfg(
            depth=2,
            branching_factor=1,
            deckies_per_lan_min=1,
            deckies_per_lan_max=1,
            cross_edge_probability=0.0,
        )
    )
    h, _ = await _hydrate_plan(repo, plan)
    for lan in h["lans"]:
        lan["host_uuid"] = "host-A"
    assert "BRIDGE_HOST_SPLIT" not in [i.code for i in validate(h)]


@pytest.mark.anyio
async def test_bridge_decky_split_across_hosts_fails(repo):
    plan = generate(
        _cfg(
            depth=2,
            branching_factor=1,
            deckies_per_lan_min=1,
            deckies_per_lan_max=1,
            cross_edge_probability=0.0,
        )
    )
    h, _ = await _hydrate_plan(repo, plan)
    # Find a bridge decky (one connected to ≥2 LANs).
    decky_lans: dict[str, list[str]] = {}
    for e in h["edges"]:
        decky_lans.setdefault(e["decky_uuid"], []).append(e["lan_id"])
    bridge_lan_ids = next(
        (lids for lids in decky_lans.values() if len(lids) >= 2), None
    )
    assert bridge_lan_ids, "test setup expected ≥1 bridge decky"
    # Pin its two LANs to different hosts.
    lans_by_id = {lan["id"]: lan for lan in h["lans"]}
    lans_by_id[bridge_lan_ids[0]]["host_uuid"] = "host-A"
    lans_by_id[bridge_lan_ids[1]]["host_uuid"] = "host-B"

    codes = [i.code for i in validate(h) if i.severity == "error"]
    assert "BRIDGE_HOST_SPLIT" in codes


# --------------------------------------------------------------------- deployer hook


@pytest.mark.anyio
async def test_deploy_aborts_on_validation_error(repo, tmp_path, monkeypatch):
    """Broken topology must be rejected before any Docker call."""
    monkeypatch.chdir(tmp_path)
    plan = generate(_cfg())
    tid = await persist(repo, plan)

    # Corrupt the persisted state: strip the DMZ flag.
    lan = (await repo.list_lans_for_topology(tid))[0]
    # Use raw repo path — SQLModel UPDATE via get + setattr.
    from sqlmodel import select
    from decnet.web.db.models import LAN
    async with repo._session() as s:
        row = (await s.execute(select(LAN).where(LAN.id == lan["id"]))).scalar_one()
        row.is_dmz = False
        s.add(row)
        await s.commit()

    class _ShouldNotCall:
        def from_env(self):  # noqa: D401
            raise AssertionError("docker must not be called on a rejected topology")

    with patch("decnet.engine.deployer.docker", _ShouldNotCall()):
        with pytest.raises(ValidationError):
            await deploy_topology(repo, tid)

    topo = await repo.get_topology(tid)
    assert topo["status"] == TopologyStatus.PENDING
