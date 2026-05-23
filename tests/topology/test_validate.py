# SPDX-License-Identifier: AGPL-3.0-or-later
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
    check_gateway_homed_in_dmz,
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
        row = (await s.execute(select(LAN).where(LAN.id == lan.id))).scalar_one()
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
    assert topo.status == TopologyStatus.PENDING


# --------------------------------------------------------------------- gateway-in-dmz


def _make_hydrated(*, dmz_id="dmz-id", internal_id="int-id") -> dict:
    """Tiny hand-rolled hydrated dict for hermetic check_* unit tests."""
    return {
        "topology": {"id": "t", "status": "pending"},
        "lans": [
            {"id": dmz_id, "name": "dmz", "subnet": "10.0.0.0/24", "is_dmz": True},
            {"id": internal_id, "name": "internal", "subnet": "10.0.1.0/24", "is_dmz": False},
        ],
        "deckies": [],
        "edges": [],
    }


def test_check_gateway_homed_in_dmz_passes_when_gateway_is_in_dmz() -> None:
    h = _make_hydrated()
    h["deckies"].append({
        "uuid": "d1", "name": "gw",
        "decky_config": {"name": "gw", "forwards_l3": True},
        "services": ["ssh"],
    })
    h["edges"].append({
        "decky_uuid": "d1", "lan_id": "dmz-id",
        "is_bridge": False, "forwards_l3": True,
    })
    assert check_gateway_homed_in_dmz(h) == []


def test_check_gateway_homed_in_dmz_fails_when_gateway_is_internal() -> None:
    h = _make_hydrated()
    h["deckies"].append({
        "uuid": "d1", "name": "gw",
        "decky_config": {"name": "gw", "forwards_l3": True},
        "services": ["ssh"],
    })
    # Home edge points at the internal LAN, not the DMZ.
    h["edges"].append({
        "decky_uuid": "d1", "lan_id": "int-id",
        "is_bridge": False, "forwards_l3": True,
    })
    issues = check_gateway_homed_in_dmz(h)
    assert len(issues) == 1
    assert issues[0].code == "GATEWAY_NOT_IN_DMZ"


def test_check_gateway_homed_in_dmz_ignores_non_gateway_deckies() -> None:
    h = _make_hydrated()
    h["deckies"].append({
        "uuid": "d1", "name": "web",
        "decky_config": {"name": "web"},  # forwards_l3 absent
        "services": ["ssh"],
    })
    h["edges"].append({
        "decky_uuid": "d1", "lan_id": "int-id",
        "is_bridge": False,
    })
    assert check_gateway_homed_in_dmz(h) == []


def test_check_gateway_homed_in_dmz_uses_non_bridge_edge_as_home() -> None:
    """Multi-homed gateway: home is the non-bridge edge, not the bridge edge."""
    h = _make_hydrated()
    h["deckies"].append({
        "uuid": "d1", "name": "gw",
        "decky_config": {"name": "gw", "forwards_l3": True},
        "services": ["ssh"],
    })
    # Bridge edge first (would be picked by a naive 'first edge' rule).
    h["edges"].append({
        "decky_uuid": "d1", "lan_id": "int-id",
        "is_bridge": True, "forwards_l3": False,
    })
    h["edges"].append({
        "decky_uuid": "d1", "lan_id": "dmz-id",
        "is_bridge": False, "forwards_l3": True,
    })
    # Home is the DMZ via the non-bridge edge → no issue.
    assert check_gateway_homed_in_dmz(h) == []
