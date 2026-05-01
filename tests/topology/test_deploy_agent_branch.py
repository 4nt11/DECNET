"""Agent-branch routing inside deploy_topology / teardown_topology.

Exercises the target_host_uuid branch added in Step 6.  We never hit a
real agent — AgentClient is swapped out for a recording fake so we
assert the right hydrated blob + version hash are forwarded and the
master's status machine advances as expected.
"""
from __future__ import annotations

from typing import Any

import pytest

from decnet.engine import deployer as _deployer
from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.hashing import canonical_hash
from decnet.topology.persistence import persist
from decnet.topology.status import TopologyStatus
from decnet.web.db.factory import get_repository


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="agent-branch",
        mode="agent",
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=7,
    )
    base.update(kw)
    return TopologyConfig(**base)


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "agent-branch.db"))
    await r.initialize()
    return r


async def _seed_host(repo, uuid_: str = "h-1") -> None:
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
    """Records every call; never touches the network."""

    instances: list["_FakeAgentClient"] = []

    def __init__(self, *, host: dict[str, Any]) -> None:
        self.host = host
        self.calls: list[tuple[str, tuple, dict]] = []
        _FakeAgentClient.instances.append(self)

    async def __aenter__(self) -> "_FakeAgentClient":
        return self

    async def __aexit__(self, *_exc) -> None:
        return None

    async def apply_topology(self, hydrated, version_hash):
        self.calls.append(("apply", (hydrated, version_hash), {}))
        return {"status": "applied", "version_hash": version_hash}

    async def teardown_topology(self, topology_id):
        self.calls.append(("teardown", (topology_id,), {}))
        return {"status": "torn_down", "topology_id": topology_id}


@pytest.fixture
def fake_agent(monkeypatch: pytest.MonkeyPatch):
    _FakeAgentClient.instances.clear()
    # Patch the import site inside the local functions; they do
    # `from decnet.swarm.client import AgentClient` at call time.
    import decnet.swarm.client as _swarm_client
    monkeypatch.setattr(_swarm_client, "AgentClient", _FakeAgentClient)
    return _FakeAgentClient


@pytest.mark.anyio
async def test_deploy_on_agent_routes_via_agent_client(repo, fake_agent) -> None:
    await _seed_host(repo, "h-deploy")
    plan = generate(_cfg())
    tid = await persist(repo, plan, target_host_uuid="h-deploy")

    await _deployer.deploy_topology(repo, tid)

    # Exactly one AgentClient, one apply call.
    assert len(fake_agent.instances) == 1
    inst = fake_agent.instances[0]
    assert inst.host["uuid"] == "h-deploy"
    assert len(inst.calls) == 1
    verb, (hydrated, version_hash), _ = inst.calls[0]
    assert verb == "apply"
    assert hydrated["topology"]["id"] == tid
    assert version_hash == canonical_hash(hydrated)

    topo = await repo.get_topology(tid)
    assert topo.status == TopologyStatus.ACTIVE


@pytest.mark.anyio
async def test_deploy_on_agent_failure_marks_failed(repo, monkeypatch) -> None:
    await _seed_host(repo, "h-fail")
    plan = generate(_cfg(name="agent-fail"))
    tid = await persist(repo, plan, target_host_uuid="h-fail")

    class _BoomClient(_FakeAgentClient):
        async def apply_topology(self, hydrated, version_hash):
            raise RuntimeError("agent refused")

    import decnet.swarm.client as _swarm_client
    monkeypatch.setattr(_swarm_client, "AgentClient", _BoomClient)

    with pytest.raises(RuntimeError, match="agent refused"):
        await _deployer.deploy_topology(repo, tid)

    topo = await repo.get_topology(tid)
    assert topo.status == TopologyStatus.FAILED


@pytest.mark.anyio
async def test_deploy_on_agent_unknown_host_raises(repo, fake_agent) -> None:
    plan = generate(_cfg(name="agent-missing"))
    tid = await persist(repo, plan, target_host_uuid="nope")

    with pytest.raises(ValueError, match="unknown swarm host"):
        await _deployer.deploy_topology(repo, tid)

    # No AgentClient should ever be constructed for a nonexistent host.
    assert fake_agent.instances == []


@pytest.mark.anyio
async def test_teardown_on_agent_routes_via_agent_client(repo, fake_agent) -> None:
    await _seed_host(repo, "h-teardown")
    plan = generate(_cfg(name="agent-down"))
    tid = await persist(repo, plan, target_host_uuid="h-teardown")

    # Seed into an ACTIVE state the teardown will accept.
    from decnet.topology.persistence import transition_status
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(repo, tid, TopologyStatus.ACTIVE)

    await _deployer.teardown_topology(repo, tid)

    inst = fake_agent.instances[-1]
    assert inst.host["uuid"] == "h-teardown"
    assert inst.calls == [("teardown", (tid,), {})]

    topo = await repo.get_topology(tid)
    assert topo.status == TopologyStatus.TORN_DOWN
