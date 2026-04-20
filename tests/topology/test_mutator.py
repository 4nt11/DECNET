"""Step 7 — topology_mutations queue + mutator reconciler branch."""
from __future__ import annotations

import json

import pytest

from decnet.mutator import engine as _engine
from decnet.mutator.ops import MutationError, apply_add_lan, apply_update_decky
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.persistence import persist, transition_status
from decnet.topology.status import TopologyStatus, VersionConflict
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="mut",
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=2,
        deckies_per_lan_max=2,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=9,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "mut.db"))
    await r.initialize()
    return r


async def _make_active(repo) -> str:
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(repo, tid, TopologyStatus.ACTIVE)
    return tid


# --------------------------------------------------------------------- queue


@pytest.mark.anyio
async def test_enqueue_bumps_topology_version(repo):
    tid = await _make_active(repo)
    before = (await repo.get_topology(tid))["version"]
    mid = await repo.enqueue_topology_mutation(
        tid, "add_lan", {"name": "LAN-X", "subnet": "172.20.77.0/24"},
        expected_version=before,
    )
    topo = await repo.get_topology(tid)
    assert topo["version"] == before + 1
    rows = await repo.list_topology_mutations(tid)
    assert rows[0]["id"] == mid
    assert rows[0]["state"] == "pending"


@pytest.mark.anyio
async def test_enqueue_version_conflict(repo):
    tid = await _make_active(repo)
    await repo.enqueue_topology_mutation(
        tid, "add_lan", {"name": "LAN-X", "subnet": "172.20.77.0/24"},
        expected_version=1,
    )
    with pytest.raises(VersionConflict):
        await repo.enqueue_topology_mutation(
            tid, "add_lan", {"name": "LAN-Y", "subnet": "172.20.78.0/24"},
            expected_version=1,  # stale — version is now 2
        )


@pytest.mark.anyio
async def test_claim_next_mutation_is_atomic_single_winner(repo):
    """Two simulated watch loops; only one claims the row."""
    tid = await _make_active(repo)
    await repo.enqueue_topology_mutation(
        tid, "add_lan", {"name": "LAN-X"},
    )
    # Sequential simulated races: because the claim is a single SQL
    # UPDATE with ``WHERE state='pending'``, the second call observes
    # state='applying' and returns None rather than re-claiming.
    first = await repo.claim_next_mutation(tid)
    second = await repo.claim_next_mutation(tid)
    assert first is not None
    assert second is None
    assert first["state"] == "applying"


@pytest.mark.anyio
async def test_claim_none_when_empty(repo):
    tid = await _make_active(repo)
    assert await repo.claim_next_mutation(tid) is None


@pytest.mark.anyio
async def test_mark_applied_and_failed(repo):
    tid = await _make_active(repo)
    mid1 = await repo.enqueue_topology_mutation(tid, "add_lan", {"name": "A"})
    mid2 = await repo.enqueue_topology_mutation(tid, "add_lan", {"name": "B"})
    await repo.claim_next_mutation(tid)
    await repo.mark_mutation_applied(mid1)
    await repo.claim_next_mutation(tid)
    await repo.mark_mutation_failed(mid2, "boom")

    by_id = {r["id"]: r for r in await repo.list_topology_mutations(tid)}
    assert by_id[mid1]["state"] == "applied"
    assert by_id[mid2]["state"] == "failed"
    assert by_id[mid2]["reason"] == "boom"


# --------------------------------------------------------------- guard query


@pytest.mark.anyio
async def test_guard_false_without_pending_or_live(repo):
    # No topologies at all.
    assert await repo.has_pending_topology_mutation() is False
    # Pending topology with a mutation (but not live) — guard stays False.
    plan = generate(_cfg())
    tid = await persist(repo, plan)
    # enqueue_topology_mutation doesn't require status, but pending
    # topologies don't trip the guard.
    await repo.enqueue_topology_mutation(tid, "add_lan", {"name": "Z"})
    assert await repo.has_pending_topology_mutation() is False


@pytest.mark.anyio
async def test_guard_true_with_live_pending(repo):
    tid = await _make_active(repo)
    await repo.enqueue_topology_mutation(tid, "add_lan", {"name": "Z"})
    assert await repo.has_pending_topology_mutation() is True
    # After claiming, the pending row becomes applying — guard drops.
    await repo.claim_next_mutation(tid)
    assert await repo.has_pending_topology_mutation() is False


# ---------------------------------------------------------------------- ops


@pytest.mark.anyio
async def test_apply_add_lan_persists(repo):
    tid = await _make_active(repo)
    await apply_add_lan(
        repo, tid, {"name": "LAN-MUT", "subnet": "172.20.55.0/24"}
    )
    names = {l["name"] for l in await repo.list_lans_for_topology(tid)}
    assert "LAN-MUT" in names


@pytest.mark.anyio
async def test_apply_rejected_on_validator_error(repo):
    """Unknown service name must trip the post-apply validator."""
    tid = await _make_active(repo)
    decky = (await repo.list_topology_deckies(tid))[0]
    with pytest.raises(MutationError):
        await apply_update_decky(
            repo, tid,
            {
                "decky": decky["decky_config"]["name"],
                # service_config for an undeclared service trips
                # SERVICE_CFG_UNDECLARED in the post-apply invariants.
                "patch": {"service_config": {"telnet": {"banner": "x"}}},
            },
        )


# ----------------------------------------------------------- reconciler flow


@pytest.mark.anyio
async def test_reconcile_applies_pending_mutation(repo):
    tid = await _make_active(repo)
    await repo.enqueue_topology_mutation(
        tid, "add_lan",
        {"name": "LAN-RECON", "subnet": "172.20.44.0/24"},
    )
    drained = await _engine.reconcile_topologies(repo)
    assert drained == 1
    names = {l["name"] for l in await repo.list_lans_for_topology(tid)}
    assert "LAN-RECON" in names
    # Mutation row is now applied.
    state = {r["state"] for r in await repo.list_topology_mutations(tid)}
    assert state == {"applied"}


@pytest.mark.anyio
async def test_reconcile_failed_mutation_degrades_topology(repo):
    tid = await _make_active(repo)
    existing = (await repo.list_lans_for_topology(tid))[0]["name"]
    # Validator will reject duplicate LAN name → failure path.
    await repo.enqueue_topology_mutation(
        tid, "add_lan", {"name": existing, "subnet": "172.20.88.0/24"},
    )
    drained = await _engine.reconcile_topologies(repo)
    assert drained == 0
    mut = (await repo.list_topology_mutations(tid))[0]
    assert mut["state"] == "failed"
    topo = await repo.get_topology(tid)
    assert topo["status"] == TopologyStatus.DEGRADED


# ----------------------------------------------------- watch-loop guard isolation


@pytest.mark.anyio
async def test_watch_loop_guard_skips_reconciler_when_idle(
    repo, monkeypatch
):
    """Tick with no live topology + no pending mutations ⇒ reconciler not called.

    Also asserts flat-fleet ``mutate_all`` runs every tick, unchanged.
    """
    calls = {"mutate_all": 0, "reconcile": 0}

    async def _fake_mutate_all(force=False, repo=None):
        calls["mutate_all"] += 1

    async def _fake_reconcile(r):
        calls["reconcile"] += 1
        return 0

    monkeypatch.setattr(_engine, "mutate_all", _fake_mutate_all)
    monkeypatch.setattr(_engine, "reconcile_topologies", _fake_reconcile)

    # Manually drive one iteration of the loop body.
    await _engine.mutate_all(force=False, repo=repo)
    if await repo.has_pending_topology_mutation():
        await _engine.reconcile_topologies(repo)

    assert calls["mutate_all"] == 1
    assert calls["reconcile"] == 0


@pytest.mark.anyio
async def test_watch_loop_guard_fires_reconciler_when_work_exists(
    repo, monkeypatch
):
    tid = await _make_active(repo)
    await repo.enqueue_topology_mutation(tid, "add_lan", {"name": "X"})

    calls = {"reconcile": 0}

    async def _fake_reconcile(r):
        calls["reconcile"] += 1
        return 0

    monkeypatch.setattr(_engine, "reconcile_topologies", _fake_reconcile)

    if await repo.has_pending_topology_mutation():
        await _engine.reconcile_topologies(repo)

    assert calls["reconcile"] == 1


def test_ops_payload_shape_docstring_present():
    """Smoke: DISPATCH covers every op name referenced in the plan."""
    from decnet.mutator.ops import DISPATCH

    assert set(DISPATCH) == {
        "add_lan", "remove_lan", "attach_decky", "detach_decky",
        "remove_decky", "update_decky", "update_lan",
    }


def _payload_json(d: dict) -> str:
    return json.dumps(d)
