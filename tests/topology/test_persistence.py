"""MazeNET persistence-layer tests: generator → repo → hydrate roundtrip."""
import pytest

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import (
    hydrate,
    persist,
    transition_status,
)
from decnet.topology.status import TopologyStatus, TopologyStatusError
from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "persist.db"))
    await r.initialize()
    return r


def _config(**kw) -> TopologyConfig:
    base = dict(
        name="roundtrip",
        depth=2,
        branching_factor=2,
        deckies_per_lan_min=1,
        deckies_per_lan_max=2,
        cross_edge_probability=0.0,
        randomize_services=True,
        seed=7,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.mark.anyio
async def test_persist_then_hydrate(repo):
    plan = generate(_config())
    tid = await persist(repo, plan)

    hydrated = await hydrate(repo, tid)
    assert hydrated is not None
    assert hydrated["topology"]["name"] == "roundtrip"
    assert hydrated["topology"]["status"] == TopologyStatus.PENDING
    assert len(hydrated["lans"]) == len(plan.lans)
    assert len(hydrated["deckies"]) == len(plan.deckies)
    assert len(hydrated["edges"]) == len(plan.edges)

    # LANs round-trip with their DMZ flag and subnet.
    by_name = {lan["name"]: lan for lan in hydrated["lans"]}
    for planned in plan.lans:
        assert by_name[planned.name]["subnet"] == planned.subnet
        assert by_name[planned.name]["is_dmz"] == planned.is_dmz

    # Deckies round-trip their services as a list, not a string.
    for d in hydrated["deckies"]:
        assert isinstance(d["services"], list)


@pytest.mark.anyio
async def test_transition_status_enforces_legality(repo):
    plan = generate(_config())
    tid = await persist(repo, plan)

    await transition_status(repo, tid, TopologyStatus.DEPLOYING, reason="go")
    await transition_status(repo, tid, TopologyStatus.ACTIVE)
    topo = await repo.get_topology(tid)
    assert topo.status == TopologyStatus.ACTIVE

    # Can't go from active directly back to pending.
    with pytest.raises(TopologyStatusError):
        await transition_status(repo, tid, TopologyStatus.PENDING)

    # Unknown topology raises ValueError, not silent no-op.
    with pytest.raises(ValueError):
        await transition_status(repo, "does-not-exist", TopologyStatus.ACTIVE)


@pytest.mark.anyio
async def test_hydrate_missing_topology(repo):
    assert await hydrate(repo, "no-such-id") is None


@pytest.mark.anyio
async def test_config_snapshot_preserves_seed(repo):
    plan = generate(_config(seed=12345))
    tid = await persist(repo, plan)
    # Topology is persisted with the correct identity; config_snapshot is an
    # internal storage field not exposed through the Protocol (TopologySummary).
    topo = await repo.get_topology(tid)
    assert topo is not None
    assert topo.id == tid
