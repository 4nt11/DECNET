# SPDX-License-Identifier: AGPL-3.0-or-later
"""Heartbeat-driven topology resync: master flags divergent agents.

When an agent reports an applied_version_hash that differs from what
master computed for the topology pinned to that host (or reports no
topology at all while master expects one), the heartbeat handler must
set ``needs_resync=True`` on the topology row.  The mutator reconcile
loop picks it up later — tested separately.
"""
from __future__ import annotations

import pathlib
from typing import Any

import pytest
from fastapi.testclient import TestClient

from decnet.topology.config import TopologyConfig
from decnet.topology.generator import generate
from decnet.topology.hashing import canonical_hash
from decnet.topology.persistence import hydrate, persist, transition_status
from decnet.topology.status import TopologyStatus
from decnet.web.db.factory import get_repository
from decnet.web.dependencies import get_repo
from decnet.web.router.swarm import api_heartbeat as hb_mod


@pytest.fixture
def ca_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    ca = tmp_path / "ca"
    from decnet.swarm import pki
    from decnet.swarm import client as swarm_client
    from decnet.web.router.swarm import api_enroll_host as enroll_mod

    monkeypatch.setattr(pki, "DEFAULT_CA_DIR", ca)
    monkeypatch.setattr(swarm_client, "pki", pki)
    monkeypatch.setattr(enroll_mod, "pki", pki)
    return ca


@pytest.fixture
def repo(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    r = get_repository(db_path=str(tmp_path / "hb-resync.db"))
    import decnet.web.dependencies as deps
    import decnet.web.swarm_api as swarm_api_mod

    monkeypatch.setattr(deps, "repo", r)
    monkeypatch.setattr(swarm_api_mod, "repo", r)
    return r


@pytest.fixture
def client(repo, ca_dir):
    from decnet.web.swarm_api import app

    async def _override() -> Any:
        return repo

    app.dependency_overrides[get_repo] = _override
    # loopback client so operator-gated /swarm/enroll accepts the local operator.
    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        yield c
    app.dependency_overrides.clear()


def _enroll(c: TestClient, name: str) -> dict:
    r = c.post("/swarm/enroll", json={"name": name, "address": "10.0.0.5", "agent_port": 8765})
    assert r.status_code == 201, r.text
    return r.json()


def _cfg(**kw) -> TopologyConfig:
    base = dict(
        name="hb-resync",
        mode="agent",
        depth=1,
        branching_factor=1,
        deckies_per_lan_min=1,
        deckies_per_lan_max=1,
        cross_edge_probability=0.0,
        randomize_services=False,
        services_explicit=["ssh"],
        seed=3,
    )
    base.update(kw)
    return TopologyConfig(**base)


async def _persist_active(repo, host_uuid: str) -> tuple[str, str]:
    plan = generate(_cfg())
    tid = await persist(repo, plan, target_host_uuid=host_uuid)
    await transition_status(repo, tid, TopologyStatus.DEPLOYING)
    await transition_status(repo, tid, TopologyStatus.ACTIVE)
    hydrated = await hydrate(repo, tid)
    return tid, canonical_hash(hydrated)


@pytest.mark.anyio
async def test_heartbeat_matching_hash_does_not_flag(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _enroll(client, "worker-match")
    monkeypatch.setattr(hb_mod, "_extract_peer_fingerprint", lambda s: host["fingerprint"])
    tid, expected = await _persist_active(repo, host["host_uuid"])

    resp = client.post(
        "/swarm/heartbeat",
        json={
            "host_uuid": host["host_uuid"],
            "status": {"deployed": False},
            "topology": {
                "topology_id": tid,
                "applied_version_hash": expected,
                "observed": {"bridges": [], "containers": []},
            },
        },
    )
    assert resp.status_code == 204, resp.text
    row = await repo.get_topology(tid)
    assert row.needs_resync is False


@pytest.mark.anyio
async def test_heartbeat_hash_mismatch_flags_resync(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _enroll(client, "worker-drift")
    monkeypatch.setattr(hb_mod, "_extract_peer_fingerprint", lambda s: host["fingerprint"])
    tid, _ = await _persist_active(repo, host["host_uuid"])

    resp = client.post(
        "/swarm/heartbeat",
        json={
            "host_uuid": host["host_uuid"],
            "status": {"deployed": False},
            "topology": {
                "topology_id": tid,
                "applied_version_hash": "stale-hash-" + "0" * 40,
                "observed": {"bridges": [], "containers": []},
            },
        },
    )
    assert resp.status_code == 204, resp.text
    row = await repo.get_topology(tid)
    assert row.needs_resync is True


@pytest.mark.anyio
async def test_heartbeat_agent_reports_no_topology_flags_resync(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fresh-boot / wiped-cache case: agent says `null` but master expects
    an ACTIVE topology pinned here → flag for re-push."""
    host = _enroll(client, "worker-fresh")
    monkeypatch.setattr(hb_mod, "_extract_peer_fingerprint", lambda s: host["fingerprint"])
    tid, _ = await _persist_active(repo, host["host_uuid"])

    resp = client.post(
        "/swarm/heartbeat",
        json={
            "host_uuid": host["host_uuid"],
            "status": {"deployed": False},
            "topology": {
                "topology_id": None,
                "applied_version_hash": None,
                "observed": {"bridges": [], "containers": []},
            },
        },
    )
    assert resp.status_code == 204, resp.text
    row = await repo.get_topology(tid)
    assert row.needs_resync is True


@pytest.mark.anyio
async def test_heartbeat_without_topology_block_is_noop_for_resync(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Legacy agents that don't send a topology block are still valid;
    they just don't contribute to resync detection.  But we still should
    treat the absence as 'no topology reported' for a pinned ACTIVE
    topology → flag."""
    host = _enroll(client, "worker-legacy")
    monkeypatch.setattr(hb_mod, "_extract_peer_fingerprint", lambda s: host["fingerprint"])
    tid, _ = await _persist_active(repo, host["host_uuid"])

    resp = client.post(
        "/swarm/heartbeat",
        json={"host_uuid": host["host_uuid"], "status": {"deployed": False}},
    )
    assert resp.status_code == 204, resp.text
    row = await repo.get_topology(tid)
    # Absence of the topology block means agent hasn't reported anything
    # → treat like no topology reported → flag.
    assert row.needs_resync is True


@pytest.mark.anyio
async def test_heartbeat_other_host_topology_unaffected(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reports from one host must not flip resync flags on another
    host's topologies."""
    host_a = _enroll(client, "worker-a")
    host_b = client.post(
        "/swarm/enroll",
        json={"name": "worker-b", "address": "10.0.0.6", "agent_port": 8765},
    ).json()
    monkeypatch.setattr(hb_mod, "_extract_peer_fingerprint", lambda s: host_b["fingerprint"])
    tid_a, hash_a = await _persist_active(repo, host_a["host_uuid"])

    resp = client.post(
        "/swarm/heartbeat",
        json={
            "host_uuid": host_b["host_uuid"],
            "status": {"deployed": False},
            "topology": {
                "topology_id": None,
                "applied_version_hash": None,
                "observed": {},
            },
        },
    )
    assert resp.status_code == 204, resp.text
    row = await repo.get_topology(tid_a)
    assert row.needs_resync is False
