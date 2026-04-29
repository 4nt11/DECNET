"""Live materialisation contracts for decnet.mutator.ops.

These tests run each ``apply_*`` op against an active topology and
assert it triggers the right docker side-effect.  The compose runner
and docker SDK are mocked at the module-attribute level — the helpers
do lazy imports so monkeypatching the bound names works.

The DB layer is real (SQLite via ``get_repository``).  Mirror the
fixture posture used in ``tests/topology/test_mutator.py``.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from decnet.mutator.ops import (
    MutationError,
    apply_add_decky,
    apply_attach_decky,
    apply_detach_decky,
    apply_remove_decky,
    apply_update_decky,
    apply_update_lan,
)
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist, transition_status
from decnet.topology.status import TopologyStatus
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="mat",
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=2,
        deckies_per_lan_max=2,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=11,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "mat.db"))
    await r.initialize()
    return r


async def _make_active(repo) -> str:
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(repo, tid, TopologyStatus.ACTIVE)
    return tid


@pytest.fixture
def stubs(monkeypatch):
    """Patch the primitives the materialisation helpers reach into.

    Returns a small dict of ``MagicMock``s the test can assert on.
    Patching at the source modules means the helpers' lazy ``from X
    import Y`` resolves to the mocks at call time.
    """
    from decnet.engine import deployer as _deployer
    from decnet.topology import compose as _compose_mod
    import docker as _docker

    compose = MagicMock(name="_compose")
    compose_with_retry = MagicMock(name="_compose_with_retry")
    topology_compose_path = MagicMock(
        name="_topology_compose_path",
        return_value="/tmp/mat-compose.yml",
    )
    write_compose = MagicMock(name="write_topology_compose")

    monkeypatch.setattr(_deployer, "_compose", compose)
    monkeypatch.setattr(_deployer, "_compose_with_retry", compose_with_retry)
    monkeypatch.setattr(_deployer, "_topology_compose_path", topology_compose_path)
    monkeypatch.setattr(_compose_mod, "write_topology_compose", write_compose)

    # docker SDK stub — one client, one network, one container, all
    # MagicMock so the helpers' .connect / .disconnect calls land
    # somewhere we can inspect.
    network = MagicMock(name="docker_network")
    container = MagicMock(name="docker_container")
    client = MagicMock(name="docker_client")
    client.networks.get.return_value = network
    client.containers.get.return_value = container
    monkeypatch.setattr(_docker, "from_env", lambda: client)

    return {
        "compose": compose,
        "compose_with_retry": compose_with_retry,
        "write_compose": write_compose,
        "client": client,
        "network": network,
        "container": container,
    }


# ---------------- apply_add_decky --------------------------------------


@pytest.mark.anyio
async def test_add_decky_spawns_base_and_service_containers(repo, stubs):
    tid = await _make_active(repo)
    # Pick an existing LAN to attach to.
    lans = await repo.list_lans_for_topology(tid)
    home_lan = lans[0]["name"]

    await apply_add_decky(repo, tid, {
        "name": "newbox",
        "lan": home_lan,
        "services": ["ssh"],
    })

    # compose up -d --no-deps --build was called with base + ssh service.
    stubs["compose_with_retry"].assert_called()
    args, kwargs = stubs["compose_with_retry"].call_args
    assert args[:4] == ("up", "-d", "--no-deps", "--build")
    assert "newbox" in args
    assert "newbox-ssh" in args


@pytest.mark.anyio
async def test_add_decky_skips_materialisation_when_pending(repo, stubs):
    """Pending topology gets DB write only — deploy_topology will spawn."""
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    # NOTE: no transition to active.

    lans = await repo.list_lans_for_topology(tid)
    await apply_add_decky(repo, tid, {
        "name": "ghost",
        "lan": lans[0]["name"],
        "services": ["ssh"],
    })

    stubs["compose_with_retry"].assert_not_called()


# ---------------- apply_remove_decky -----------------------------------


@pytest.mark.anyio
async def test_remove_decky_stops_and_removes_containers(repo, stubs):
    tid = await _make_active(repo)
    deckies = await repo.list_topology_deckies(tid)
    target = deckies[0]
    target_name = target["decky_config"]["name"]

    await apply_remove_decky(repo, tid, {"decky": target_name})

    # Two compose invocations: stop, then rm -f.  Targets include the
    # base + each service container.
    stop_calls = [c for c in stubs["compose"].call_args_list if c.args and c.args[0] == "stop"]
    rm_calls = [c for c in stubs["compose"].call_args_list if c.args and c.args[0] == "rm"]
    assert stop_calls, "expected compose stop"
    assert rm_calls, "expected compose rm"
    assert target_name in stop_calls[0].args


# ---------------- apply_attach_decky -----------------------------------


@pytest.mark.anyio
async def test_attach_decky_calls_network_connect(repo, stubs):
    """Multi-home: SDK network.connect on the base container."""
    tid = await _make_active(repo)
    deckies = await repo.list_topology_deckies(tid)
    lans = await repo.list_lans_for_topology(tid)
    target = deckies[0]
    target_name = target["decky_config"]["name"]
    # Pick a LAN the decky isn't already on.
    home_lan = next(iter(target["decky_config"]["ips_by_lan"]))
    other_lan = next((l for l in lans if l["name"] != home_lan), None)
    if other_lan is None:
        pytest.skip("topology has only one LAN; can't multi-home")

    await apply_attach_decky(repo, tid, {
        "decky": target_name,
        "lan": other_lan["name"],
    })

    stubs["network"].connect.assert_called_once()
    _, kwargs = stubs["network"].connect.call_args
    assert "ipv4_address" in kwargs


# ---------------- apply_detach_decky -----------------------------------


@pytest.mark.anyio
async def test_detach_decky_calls_network_disconnect(repo, stubs):
    tid = await _make_active(repo)
    deckies = await repo.list_topology_deckies(tid)
    lans = await repo.list_lans_for_topology(tid)
    target = deckies[0]
    target_name = target["decky_config"]["name"]
    home_lan = next(iter(target["decky_config"]["ips_by_lan"]))
    other_lan = next((l for l in lans if l["name"] != home_lan), None)
    if other_lan is None:
        pytest.skip("topology has only one LAN")

    # Multi-home first so there's something to detach.
    await apply_attach_decky(repo, tid, {
        "decky": target_name,
        "lan": other_lan["name"],
    })
    stubs["network"].connect.reset_mock()

    await apply_detach_decky(repo, tid, {
        "decky": target_name,
        "lan": other_lan["name"],
    })

    stubs["network"].disconnect.assert_called_once()


# ---------------- apply_update_decky -----------------------------------


@pytest.mark.anyio
async def test_update_decky_services_diff_targets_only_changed(repo, stubs):
    tid = await _make_active(repo)
    deckies = await repo.list_topology_deckies(tid)
    target = deckies[0]
    target_name = target["decky_config"]["name"]
    new_services = list(target["services"]) + ["http"]

    await apply_update_decky(repo, tid, {
        "decky": target_name,
        "services": new_services,
    })

    # Up call for the added service only — base + existing services
    # are not touched.
    up_calls = [
        c for c in stubs["compose_with_retry"].call_args_list
        if c.args and c.args[0] == "up"
    ]
    assert up_calls, "expected compose up for added service"
    args = up_calls[0].args
    assert f"{target_name}-http" in args
    # The base container is NOT in the up targets — services_diff
    # strips the base from _decky_targets so we don't recreate it.
    assert target_name not in args


@pytest.mark.anyio
async def test_update_decky_forwards_l3_flip_requires_force(repo, stubs):
    tid = await _make_active(repo)
    deckies = await repo.list_topology_deckies(tid)
    target = deckies[0]
    target_name = target["decky_config"]["name"]

    with pytest.raises(MutationError, match="force=true"):
        await apply_update_decky(repo, tid, {
            "decky": target_name,
            "patch": {"forwards_l3": True},
        })

    stubs["compose_with_retry"].assert_not_called()


@pytest.mark.anyio
async def test_update_decky_forwards_l3_flip_with_force_recreates_base(
    repo, stubs,
):
    tid = await _make_active(repo)
    deckies = await repo.list_topology_deckies(tid)
    target = deckies[0]
    target_name = target["decky_config"]["name"]

    await apply_update_decky(repo, tid, {
        "decky": target_name,
        "patch": {"forwards_l3": True},
        "force": True,
    })

    # force-recreate up call against the base container.
    found = False
    for call in stubs["compose_with_retry"].call_args_list:
        if "--force-recreate" in call.args and target_name in call.args:
            found = True
            break
    assert found, "expected force-recreate up against the base"


# ---------------- apply_update_lan -------------------------------------


@pytest.mark.anyio
async def test_update_lan_rejects_subnet_change_on_active(repo, stubs):
    tid = await _make_active(repo)
    lans = await repo.list_lans_for_topology(tid)
    with pytest.raises(MutationError, match="subnet"):
        await apply_update_lan(repo, tid, {
            "name": lans[0]["name"],
            "patch": {"subnet": "10.99.99.0/24"},
        })


@pytest.mark.anyio
async def test_update_lan_allows_coord_change_on_active(repo, stubs):
    tid = await _make_active(repo)
    lans = await repo.list_lans_for_topology(tid)
    # Coord-only update — should pass through without error.
    await apply_update_lan(repo, tid, {
        "name": lans[0]["name"],
        "x": 42.0,
        "y": 84.0,
    })
    # No docker work for coord-only.
    stubs["compose"].assert_not_called()
    stubs["compose_with_retry"].assert_not_called()
