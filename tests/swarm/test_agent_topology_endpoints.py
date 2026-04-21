"""Agent topology endpoints — contract-level tests with mocked ops."""
from __future__ import annotations

import pathlib

import pytest
from fastapi.testclient import TestClient

from decnet.agent import app as _agent_app
from decnet.agent import topology_ops as _ops
from decnet.agent.topology_store import AlreadyApplied


@pytest.fixture(autouse=True)
def _isolate_store(monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path):
    """Point the singleton at a tmp dir and reset it between tests."""
    monkeypatch.setenv("DECNET_AGENT_DIR", str(tmp_path))
    # Force a fresh store per test.
    if _agent_app._topology_store is not None:
        _agent_app._topology_store.close()
    _agent_app._topology_store = None
    yield
    if _agent_app._topology_store is not None:
        _agent_app._topology_store.close()
    _agent_app._topology_store = None


def _hydrated(topology_id: str = "top-1") -> dict:
    return {
        "topology": {"id": topology_id, "name": "n", "mode": "agent"},
        "lans": [],
        "deckies": [],
        "edges": [],
    }


def test_topology_state_idle() -> None:
    client = TestClient(_agent_app.app)
    resp = client.get("/topology/state")
    assert resp.status_code == 200
    body = resp.json()
    assert body["topology_id"] is None
    assert body["applied_version_hash"] is None
    assert "observed" in body


def test_topology_apply_routes_to_ops(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict = {}

    async def _fake_apply(hydrated, version_hash, store):
        called["hydrated"] = hydrated
        called["version_hash"] = version_hash
        # Simulate ops bookkeeping.
        store.put(hydrated["topology"]["id"], version_hash, hydrated)

    monkeypatch.setattr(_ops, "apply", _fake_apply)

    client = TestClient(_agent_app.app)
    resp = client.post(
        "/topology/apply",
        json={"hydrated": _hydrated(), "version_hash": "abc"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "applied", "version_hash": "abc"}
    assert called["version_hash"] == "abc"


def test_topology_apply_hash_mismatch_is_400(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _boom(*_a, **_kw):
        raise _ops.HashMismatch("master hash != agent hash")

    monkeypatch.setattr(_ops, "apply", _boom)

    client = TestClient(_agent_app.app)
    resp = client.post(
        "/topology/apply",
        json={"hydrated": _hydrated(), "version_hash": "wrong"},
    )
    assert resp.status_code == 400
    assert "hash" in resp.json()["detail"].lower()


def test_topology_apply_conflict_is_409(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _boom(*_a, **_kw):
        raise AlreadyApplied("another topology already applied")

    monkeypatch.setattr(_ops, "apply", _boom)

    client = TestClient(_agent_app.app)
    resp = client.post(
        "/topology/apply",
        json={"hydrated": _hydrated("top-2"), "version_hash": "h"},
    )
    assert resp.status_code == 409


def test_topology_apply_docker_failure_is_500_and_records_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _boom(*_a, **_kw):
        raise RuntimeError("docker down")

    monkeypatch.setattr(_ops, "apply", _boom)
    client = TestClient(_agent_app.app)
    resp = client.post(
        "/topology/apply",
        json={"hydrated": _hydrated("top-err"), "version_hash": "h"},
    )
    assert resp.status_code == 500
    assert "docker down" in resp.json()["detail"]


def test_topology_teardown_routes_to_ops(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict = {}

    async def _fake_teardown(topology_id, store):
        called["topology_id"] = topology_id
        store.clear(topology_id)

    monkeypatch.setattr(_ops, "teardown", _fake_teardown)

    client = TestClient(_agent_app.app)
    resp = client.post(
        "/topology/teardown", json={"topology_id": "top-gone"}
    )
    assert resp.status_code == 200
    assert called["topology_id"] == "top-gone"


def test_topology_teardown_failure_is_500(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _boom(*_a, **_kw):
        raise RuntimeError("compose refused")

    monkeypatch.setattr(_ops, "teardown", _boom)

    client = TestClient(_agent_app.app)
    resp = client.post(
        "/topology/teardown", json={"topology_id": "top-1"}
    )
    assert resp.status_code == 500


def test_routes_registered() -> None:
    paths = {r.path for r in _agent_app.app.routes if hasattr(r, "path")}
    assert {"/topology/apply", "/topology/teardown", "/topology/state"} <= paths
