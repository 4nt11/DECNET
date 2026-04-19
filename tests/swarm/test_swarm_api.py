"""Unit tests for the SWARM controller FastAPI app.

Covers the enrollment, host-management, and deployment dispatch routes.
The AgentClient is stubbed so we exercise the controller's logic without
a live mTLS peer (that path has its own roundtrip test).
"""
from __future__ import annotations

import pathlib
from typing import Any

import pytest
from fastapi.testclient import TestClient

from decnet.web.db.factory import get_repository
from decnet.web.dependencies import get_repo


@pytest.fixture
def ca_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    """Redirect the PKI default CA path into tmp so the test CA never
    touches ``~/.decnet/ca``."""
    ca = tmp_path / "ca"
    from decnet.swarm import pki

    monkeypatch.setattr(pki, "DEFAULT_CA_DIR", ca)
    # Also patch the already-imported references inside client.py / routers.
    from decnet.swarm import client as swarm_client
    from decnet.web.router.swarm import api_enroll_host as enroll_mod

    monkeypatch.setattr(swarm_client, "pki", pki)
    monkeypatch.setattr(enroll_mod, "pki", pki)
    return ca


@pytest.fixture
def repo(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    r = get_repository(db_path=str(tmp_path / "swarm.db"))
    # The controller's lifespan initialises the module-level `repo` in
    # decnet.web.dependencies.  Swap that singleton for our test repo so
    # schema creation targets the temp DB.
    import decnet.web.dependencies as deps
    import decnet.web.swarm_api as swarm_api_mod

    monkeypatch.setattr(deps, "repo", r)
    monkeypatch.setattr(swarm_api_mod, "repo", r)
    return r


@pytest.fixture
def client(repo, ca_dir: pathlib.Path):
    from decnet.web.swarm_api import app

    async def _override() -> Any:
        return repo

    app.dependency_overrides[get_repo] = _override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------- /enroll


def test_enroll_creates_host_and_returns_bundle(client: TestClient) -> None:
    resp = client.post(
        "/swarm/enroll",
        json={"name": "worker-a", "address": "10.0.0.5", "agent_port": 8765},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["name"] == "worker-a"
    assert body["address"] == "10.0.0.5"
    assert "-----BEGIN CERTIFICATE-----" in body["worker_cert_pem"]
    assert "-----BEGIN PRIVATE KEY-----" in body["worker_key_pem"]
    assert "-----BEGIN CERTIFICATE-----" in body["ca_cert_pem"]
    assert len(body["fingerprint"]) == 64  # sha256 hex


def test_enroll_rejects_duplicate_name(client: TestClient) -> None:
    payload = {"name": "worker-dup", "address": "10.0.0.6", "agent_port": 8765}
    assert client.post("/swarm/enroll", json=payload).status_code == 201
    resp2 = client.post("/swarm/enroll", json=payload)
    assert resp2.status_code == 409


# ---------------------------------------------------------------- /hosts


def test_list_hosts_empty(client: TestClient) -> None:
    resp = client.get("/swarm/hosts")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_and_get_host_after_enroll(client: TestClient) -> None:
    reg = client.post(
        "/swarm/enroll",
        json={"name": "worker-b", "address": "10.0.0.7", "agent_port": 8765},
    ).json()
    uuid = reg["host_uuid"]

    lst = client.get("/swarm/hosts").json()
    assert len(lst) == 1
    assert lst[0]["name"] == "worker-b"

    one = client.get(f"/swarm/hosts/{uuid}").json()
    assert one["uuid"] == uuid
    assert one["status"] == "enrolled"


def test_decommission_removes_host_and_bundle(
    client: TestClient, ca_dir: pathlib.Path
) -> None:
    reg = client.post(
        "/swarm/enroll",
        json={"name": "worker-c", "address": "10.0.0.8", "agent_port": 8765},
    ).json()
    uuid = reg["host_uuid"]

    bundle_dir = ca_dir / "workers" / "worker-c"
    assert bundle_dir.is_dir()

    resp = client.delete(f"/swarm/hosts/{uuid}")
    assert resp.status_code == 204
    assert client.get(f"/swarm/hosts/{uuid}").status_code == 404
    assert not bundle_dir.exists()


# ---------------------------------------------------------------- /deploy


class _StubAgentClient:
    """Minimal async-context-manager stub mirroring ``AgentClient``."""

    deployed: list[dict[str, Any]] = []
    torn_down: list[dict[str, Any]] = []

    def __init__(self, host: dict[str, Any] | None = None, **_: Any) -> None:
        self._host = host or {}

    async def __aenter__(self) -> "_StubAgentClient":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def health(self) -> dict[str, Any]:
        return {"status": "ok"}

    async def deploy(self, config: Any, **kw: Any) -> dict[str, Any]:
        _StubAgentClient.deployed.append(
            {"host": self._host.get("name"), "deckies": [d.name for d in config.deckies]}
        )
        return {"status": "deployed", "deckies": len(config.deckies)}

    async def teardown(self, decky_id: str | None = None) -> dict[str, Any]:
        _StubAgentClient.torn_down.append(
            {"host": self._host.get("name"), "decky_id": decky_id}
        )
        return {"status": "torn_down"}


@pytest.fixture
def stub_agent(monkeypatch: pytest.MonkeyPatch):
    _StubAgentClient.deployed.clear()
    _StubAgentClient.torn_down.clear()
    from decnet.web.router.swarm import api_deploy_swarm as deploy_mod
    from decnet.web.router.swarm import api_teardown_swarm as teardown_mod
    from decnet.web.router.swarm import api_check_hosts as check_mod

    monkeypatch.setattr(deploy_mod, "AgentClient", _StubAgentClient)
    monkeypatch.setattr(teardown_mod, "AgentClient", _StubAgentClient)
    monkeypatch.setattr(check_mod, "AgentClient", _StubAgentClient)
    return _StubAgentClient


def _decky_dict(name: str, host_uuid: str, ip: str) -> dict[str, Any]:
    return {
        "name": name,
        "ip": ip,
        "services": ["ssh"],
        "distro": "debian",
        "base_image": "debian:bookworm-slim",
        "hostname": name,
        "host_uuid": host_uuid,
    }


def test_deploy_shards_across_hosts(client: TestClient, stub_agent) -> None:
    h1 = client.post(
        "/swarm/enroll",
        json={"name": "w1", "address": "10.0.0.1", "agent_port": 8765},
    ).json()
    h2 = client.post(
        "/swarm/enroll",
        json={"name": "w2", "address": "10.0.0.2", "agent_port": 8765},
    ).json()

    cfg = {
        "mode": "swarm",
        "interface": "eth0",
        "subnet": "192.168.1.0/24",
        "gateway": "192.168.1.1",
        "deckies": [
            _decky_dict("decky-01", h1["host_uuid"], "192.168.1.10"),
            _decky_dict("decky-02", h1["host_uuid"], "192.168.1.11"),
            _decky_dict("decky-03", h2["host_uuid"], "192.168.1.12"),
        ],
    }
    resp = client.post("/swarm/deploy", json={"config": cfg})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["results"]) == 2
    assert all(r["ok"] for r in body["results"])

    by_host = {d["host"]: d["deckies"] for d in stub_agent.deployed}
    assert by_host["w1"] == ["decky-01", "decky-02"]
    assert by_host["w2"] == ["decky-03"]


def test_deploy_rejects_missing_host_uuid(client: TestClient, stub_agent) -> None:
    cfg = {
        "mode": "swarm",
        "interface": "eth0",
        "subnet": "192.168.1.0/24",
        "gateway": "192.168.1.1",
        "deckies": [
            {
                "name": "decky-01",
                "ip": "192.168.1.10",
                "services": ["ssh"],
                "distro": "debian",
                "base_image": "debian:bookworm-slim",
                "hostname": "decky-01",
                # host_uuid deliberately omitted
            }
        ],
    }
    resp = client.post("/swarm/deploy", json={"config": cfg})
    assert resp.status_code == 400
    assert "host_uuid" in resp.json()["detail"]


def test_deploy_rejects_non_swarm_mode(client: TestClient, stub_agent) -> None:
    cfg = {
        "mode": "unihost",
        "interface": "eth0",
        "subnet": "192.168.1.0/24",
        "gateway": "192.168.1.1",
        "deckies": [_decky_dict("decky-01", "fake-uuid", "192.168.1.10")],
    }
    resp = client.post("/swarm/deploy", json={"config": cfg})
    assert resp.status_code == 400


def test_teardown_all_hosts(client: TestClient, stub_agent) -> None:
    for i, addr in enumerate(("10.0.0.1", "10.0.0.2"), start=1):
        client.post(
            "/swarm/enroll",
            json={"name": f"td{i}", "address": addr, "agent_port": 8765},
        )
    resp = client.post("/swarm/teardown", json={})
    assert resp.status_code == 200
    assert len(resp.json()["results"]) == 2
    assert {t["host"] for t in stub_agent.torn_down} == {"td1", "td2"}


# ---------------------------------------------------------------- /check


def test_check_marks_hosts_active(client: TestClient, stub_agent) -> None:
    h = client.post(
        "/swarm/enroll",
        json={"name": "probe-w", "address": "10.0.0.9", "agent_port": 8765},
    ).json()

    resp = client.post("/swarm/check")
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 1
    assert results[0]["reachable"] is True

    one = client.get(f"/swarm/hosts/{h['host_uuid']}").json()
    assert one["status"] == "active"
    assert one["last_heartbeat"] is not None


# ---------------------------------------------------------------- /deckies


def test_list_deckies_empty(client: TestClient) -> None:
    resp = client.get("/swarm/deckies")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_deckies_joins_host_identity(client: TestClient, repo) -> None:
    import asyncio

    h1 = client.post(
        "/swarm/enroll",
        json={"name": "deck-host-1", "address": "10.0.0.11", "agent_port": 8765},
    ).json()
    h2 = client.post(
        "/swarm/enroll",
        json={"name": "deck-host-2", "address": "10.0.0.12", "agent_port": 8765},
    ).json()

    async def _seed() -> None:
        await repo.upsert_decky_shard({
            "decky_name": "decky-01", "host_uuid": h1["host_uuid"],
            "services": ["ssh"], "state": "running",
        })
        await repo.upsert_decky_shard({
            "decky_name": "decky-02", "host_uuid": h2["host_uuid"],
            "services": ["smb", "ssh"], "state": "failed", "last_error": "boom",
        })

    asyncio.get_event_loop().run_until_complete(_seed())

    rows = client.get("/swarm/deckies").json()
    assert len(rows) == 2
    by_name = {r["decky_name"]: r for r in rows}
    assert by_name["decky-01"]["host_name"] == "deck-host-1"
    assert by_name["decky-01"]["host_address"] == "10.0.0.11"
    assert by_name["decky-01"]["state"] == "running"
    assert by_name["decky-02"]["services"] == ["smb", "ssh"]
    assert by_name["decky-02"]["last_error"] == "boom"

    # host_uuid filter
    only = client.get(f"/swarm/deckies?host_uuid={h1['host_uuid']}").json()
    assert [r["decky_name"] for r in only] == ["decky-01"]

    # state filter
    failed = client.get("/swarm/deckies?state=failed").json()
    assert [r["decky_name"] for r in failed] == ["decky-02"]


# ---------------------------------------------------------------- /health (root)


def test_root_health(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["role"] == "swarm-controller"
