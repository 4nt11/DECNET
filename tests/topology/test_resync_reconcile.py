"""Mutator reconcile loop + deployer.resync_agent_topology.

Covers the last mile of Step 7: once the heartbeat handler flags a
topology as ``needs_resync``, the mutator's ``reconcile_agent_resyncs``
pass must pick it up, re-push via AgentClient, and clear the flag.
Failures must leave the flag set so the next tick retries.
"""
from __future__ import annotations

from typing import Any

import pytest

from decnet.engine import deployer as _deployer
from decnet.mutator import engine as _mut_engine
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.hashing import canonical_hash
from decnet.topology.persistence import hydrate, persist, transition_status
from decnet.topology.status import TopologyStatus
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="resync",
        mode="agent",
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
    r = get_repository(db_path=str(tmp_path / "resync.db"))
    await r.initialize()
    return r


async def _seed_host(repo, uuid_: str) -> None:
    await repo.add_swarm_host(
        {
            "uuid": uuid_,
            "name": f"host-{uuid_}",
            "address": "10.9.9.9",
            "agent_port": 8765,
            "status": "active",
            "client_cert_fingerprint": "a" * 64,
            "cert_bundle_path": "/tmp/ignored",
        }
    )


class _FakeAgentClient:
    instances: list["_FakeAgentClient"] = []

    def __init__(self, *, host: dict[str, Any]) -> None:
        self.host = host
        self.calls: list[tuple[str, tuple]] = []
        _FakeAgentClient.instances.append(self)

    async def __aenter__(self) -> "_FakeAgentClient":
        return self

    async def __aexit__(self, *_exc) -> None:
        return None

    async def apply_topology(self, hydrated, version_hash):
        self.calls.append(("apply", (hydrated, version_hash)))
        return {"status": "applied", "version_hash": version_hash}


@pytest.fixture
def fake_agent(monkeypatch: pytest.MonkeyPatch):
    _FakeAgentClient.instances.clear()
    import decnet.swarm.client as _swarm_client
    monkeypatch.setattr(_swarm_client, "AgentClient", _FakeAgentClient)
    return _FakeAgentClient


async def _active_topology(repo, host_uuid: str) -> tuple[str, str]:
    plan = generate(_cfg())
    tid = await persist(repo, plan, target_host_uuid=host_uuid)
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(repo, tid, TopologyStatus.ACTIVE)
    hydrated = await hydrate(repo, tid)
    return tid, canonical_hash(hydrated)


@pytest.mark.anyio
async def test_resync_agent_topology_pushes_current_hash(repo, fake_agent) -> None:
    await _seed_host(repo, "h-sync")
    tid, expected = await _active_topology(repo, "h-sync")

    await _deployer.resync_agent_topology(repo, tid)

    assert len(fake_agent.instances) == 1
    inst = fake_agent.instances[0]
    assert inst.calls[0][0] == "apply"
    _, (hydrated, version_hash) = inst.calls[0]
    assert version_hash == expected
    assert hydrated["topology"]["id"] == tid

    row = await repo.get_topology(tid)
    assert row["status"] == TopologyStatus.ACTIVE  # unchanged


@pytest.mark.anyio
async def test_resync_rejects_master_local_topology(repo) -> None:
    plan = generate(_cfg(mode="unihost"))
    tid = await persist(repo, plan, target_host_uuid=None)
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(repo, tid, TopologyStatus.ACTIVE)

    with pytest.raises(ValueError, match="no target_host_uuid"):
        await _deployer.resync_agent_topology(repo, tid)


@pytest.mark.anyio
async def test_reconcile_agent_resyncs_drains_flag(repo, fake_agent) -> None:
    await _seed_host(repo, "h-drain")
    tid, _ = await _active_topology(repo, "h-drain")
    await repo.set_topology_resync(tid, True)

    drained = await _mut_engine.reconcile_agent_resyncs(repo)
    assert drained == 1
    row = await repo.get_topology(tid)
    assert row["needs_resync"] is False
    assert len(fake_agent.instances) == 1


@pytest.mark.anyio
async def test_reconcile_retains_flag_on_push_failure(repo, monkeypatch) -> None:
    await _seed_host(repo, "h-boom")
    tid, _ = await _active_topology(repo, "h-boom")
    await repo.set_topology_resync(tid, True)

    class _Boom:
        def __init__(self, *, host): ...
        async def __aenter__(self): return self
        async def __aexit__(self, *_): return None
        async def apply_topology(self, *_a, **_k):
            raise RuntimeError("agent unreachable")

    import decnet.swarm.client as _swarm_client
    monkeypatch.setattr(_swarm_client, "AgentClient", _Boom)

    drained = await _mut_engine.reconcile_agent_resyncs(repo)
    assert drained == 0
    row = await repo.get_topology(tid)
    assert row["needs_resync"] is True  # still flagged — next tick retries


@pytest.mark.anyio
async def test_reconcile_noop_when_nothing_flagged(repo, fake_agent) -> None:
    await _seed_host(repo, "h-idle")
    await _active_topology(repo, "h-idle")
    drained = await _mut_engine.reconcile_agent_resyncs(repo)
    assert drained == 0
    assert fake_agent.instances == []
