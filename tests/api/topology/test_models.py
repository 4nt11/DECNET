"""Phase 3 Step 1 — parity between repo dict output and Pydantic DTOs.

These tests pin the contract that repo-hydrated dicts deserialize
cleanly into the REST DTOs.  If a repo-row shape drifts, the DTO test
fails before any endpoint rides on the stale contract.
"""
from __future__ import annotations

import pytest

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import hydrate, persist, transition_status
from decnet.topology.status import TopologyStatus
from decnet.web.db.factory import get_repository
from decnet.web.db.models import (
    DeckyRow,
    EdgeRow,
    LANRow,
    MutationEnqueueRequest,
    MutationRow,
    TopologyDetail,
    TopologyGenerateRequest,
    TopologyListResponse,
    TopologyStatusEventRow,
    TopologySummary,
)
from decnet.web.router.topology import topology_router


def _cfg() -> TopologyConfig:
    return TopologyConfig(
        name="dto-parity",
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        services_explicit=["ssh"],
        randomize_services=False,
        seed=0,
    )


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "dto.db"))
    await r.initialize()
    return r


def test_router_skeleton_mounted():
    """topology_router lives under /topologies and is import-safe."""
    assert topology_router.prefix == "/topologies"
    assert "topologies" in (topology_router.tags or [])


def test_generate_request_accepts_cli_shape():
    """TopologyGenerateRequest mirrors the CLI flags."""
    req = TopologyGenerateRequest(
        name="n",
        depth=2,
        branching_factor=2,
        deckies_per_lan_min=1,
        deckies_per_lan_max=3,
        services_explicit=["ssh", "ftp"],
        randomize_services=False,
        seed=7,
    )
    assert req.depth == 2
    assert req.services_explicit == ["ssh", "ftp"]


def test_mutation_request_rejects_unknown_op():
    """Literal guard is what gives the frontend a free 422 contract."""
    with pytest.raises(ValueError):
        MutationEnqueueRequest(op="teleport_lan", payload={})


@pytest.mark.anyio
async def test_summary_accepts_repo_topology_row(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    row = await repo.get_topology(tid)
    summary = TopologySummary(**row)
    assert summary.id == tid
    assert summary.version == 1


@pytest.mark.anyio
async def test_detail_accepts_hydrated_shape(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    hydrated = await hydrate(repo, tid)
    detail = TopologyDetail(
        topology=TopologySummary(**hydrated["topology"]),
        lans=[LANRow(**l) for l in hydrated["lans"]],
        deckies=[DeckyRow(**d) for d in hydrated["deckies"]],
        edges=[EdgeRow(**e) for e in hydrated["edges"]],
    )
    assert detail.topology.id == tid
    assert len(detail.lans) == len(hydrated["lans"])
    assert len(detail.deckies) == len(hydrated["deckies"])


@pytest.mark.anyio
async def test_mutation_row_accepts_repo_row(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    mid = await repo.enqueue_topology_mutation(
        tid, "add_lan", {"name": "LAN-X"}
    )
    rows = await repo.list_topology_mutations(tid)
    assert rows and rows[0]["id"] == mid
    m = MutationRow(**rows[0])
    assert m.op == "add_lan"
    assert m.payload == {"name": "LAN-X"}


@pytest.mark.anyio
async def test_status_event_row_accepts_repo_row(repo):
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    events = await repo.list_topology_status_events(tid)
    assert events
    TopologyStatusEventRow(**events[0])


def test_list_response_envelope_shape():
    resp = TopologyListResponse(total=0, limit=50, offset=0, data=[])
    assert resp.total == 0
    assert resp.data == []
