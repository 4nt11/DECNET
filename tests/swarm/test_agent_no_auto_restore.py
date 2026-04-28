"""Step 8 regression: the agent must NEVER auto-restore a topology on boot.

Guiding rule: master is authoritative, agent is a dumb executor.  If an
agent restarts with a stale applied_topology row in its local cache, it
must not try to replay `docker-compose up` on its own — that would
create a split-brain where a decommissioned topology suddenly reappears
without the master's consent.  Instead the agent simply reports whatever
it has via GET /topology/state + heartbeat; master decides whether to
re-push.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from decnet.agent import app as agent_app
from decnet.agent.topology_store import TopologyStore


def _seed_applied_row(db_path: Path, topology_id: str, hash_: str) -> None:
    """Write a row directly — simulates a pre-existing cache from a
    previous process lifecycle."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = TopologyStore(db_path)
    try:
        store.put(topology_id, hash_, {"topology": {"id": topology_id}})
    finally:
        store.close()


@pytest.fixture
def agent_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "agent"
    d.mkdir()
    monkeypatch.setenv("DECNET_AGENT_DIR", str(d))
    # Reset the module-level cached store so the new DECNET_AGENT_DIR
    # is honoured for this test.
    monkeypatch.setattr(agent_app, "_topology_store", None)
    return d


def test_lifespan_startup_does_not_touch_docker(
    agent_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Seed a populated topology.db, spin up the agent app, and verify
    docker.from_env was never called during startup — the agent must
    wait for master instructions, not self-heal from local state."""
    _seed_applied_row(agent_dir / "topology.db", "stale-tid", "stale-hash")

    calls: list[str] = []

    def _boom(*_a, **_k):
        calls.append("docker.from_env")
        raise AssertionError("agent must not touch docker during startup")

    import docker as _docker
    monkeypatch.setattr(_docker, "from_env", _boom)

    # Bringing up the lifespan is what would run any auto-restore hook.
    with TestClient(agent_app.app) as client:
        # Sanity: health is live, no apply was triggered.
        r = client.get("/health")
        assert r.status_code == 200

    assert calls == [], "docker was contacted during agent boot"


def test_get_topology_state_reflects_cache_without_replay(
    agent_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /topology/state must return the stored hash/id unchanged.
    It may also attempt to *observe* live docker state (read-only) — we
    stub that so no real docker is required — but it must NEVER
    re-materialise bridges/containers from the cache."""
    _seed_applied_row(agent_dir / "topology.db", "t-boot", "h-boot")

    class _StubDocker:
        class networks:
            @staticmethod
            def list(): return []

        class containers:
            @staticmethod
            def list(all=False): return []

    import docker as _docker
    monkeypatch.setattr(_docker, "from_env", lambda: _StubDocker)

    with TestClient(agent_app.app) as client:
        r = client.get("/topology/state")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["topology_id"] == "t-boot"
    assert body["applied_version_hash"] == "h-boot"
    # observed is read-only — empty live state is fine, it's what the
    # master uses to decide whether to re-push.
    assert body["observed"] == {"bridges": [], "containers": []}


def test_topology_store_has_no_restore_hook() -> None:
    """Static guard: if someone adds a `restore()` / `replay()` method
    to TopologyStore this test will fail, forcing them to re-read the
    module docstring and the Step 8 rationale before merging."""
    forbidden = {"restore", "replay", "reapply", "rehydrate", "auto_restore"}
    present = {n for n in dir(TopologyStore) if not n.startswith("_")}
    overlap = forbidden & present
    assert not overlap, (
        f"TopologyStore must stay a passive cache — found {overlap}. "
        "The agent never self-heals; master decides."
    )


def test_seeded_db_survives_process_restart_verbatim(tmp_path: Path) -> None:
    """Opening a pre-populated store in a fresh process yields the same
    row — no on-open mutation, no stale-row scrubbing.  This is the
    behavior the master relies on for the 'agent reports old hash →
    needs_resync' detection path."""
    db = tmp_path / "t.db"
    # Process 1.
    s1 = TopologyStore(db)
    s1.put("t-x", "h-x", {"topology": {"id": "t-x"}})
    s1.close()

    # Raw sqlite read — confirms nothing in the file rewrites itself
    # between opens.
    with sqlite3.connect(str(db)) as raw:
        row = raw.execute(
            "SELECT topology_id, applied_version_hash, hydrated_blob_json"
            " FROM applied_topology"
        ).fetchone()
    assert row[0] == "t-x"
    assert row[1] == "h-x"
    assert json.loads(row[2]) == {"topology": {"id": "t-x"}}

    # Process 2 (new store, same file).
    s2 = TopologyStore(db)
    try:
        cur = s2.current()
        assert cur is not None
        assert cur.topology_id == "t-x"
        assert cur.applied_version_hash == "h-x"
    finally:
        s2.close()
