"""Agent FastAPI app — static/contract checks only.

We deliberately do NOT spin uvicorn up in-process here: the mTLS layer is
enforced by uvicorn itself (via --ssl-cert-reqs 2) and is validated in the
VM integration suite.  What we CAN assert in unit scope is the route
surface + request/response schema.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from decnet.agent.app import app


def test_health_endpoint() -> None:
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_status_when_not_deployed() -> None:
    client = TestClient(app)
    resp = client.get("/status")
    assert resp.status_code == 200
    body = resp.json()
    assert "deployed" in body
    assert "deckies" in body


def _seed_state(monkeypatch, tmp_path):
    """Install a fake load_state/save_state pair backed by a list cell so
    tests can both seed and re-read what the handler wrote."""
    from decnet.config import DecnetConfig, DeckyConfig
    from decnet.agent import app as _app_module

    cfg = DecnetConfig(
        mode="swarm",
        interface="eth0",
        subnet="10.66.0.0/24",
        gateway="10.66.0.1",
        deckies=[
            DeckyConfig(
                name="decky-01",
                ip="10.66.0.10",
                services=["ssh"],
                distro="debian",
                base_image="debian:bookworm-slim",
                hostname="d01",
            ),
        ],
    )
    compose_path = tmp_path / "decnet-compose.yml"
    cell = {"cfg": cfg, "compose_path": compose_path}

    def _fake_load_state():
        return (cell["cfg"], cell["compose_path"]) if cell["cfg"] is not None else None

    def _fake_save_state(c, p):
        cell["cfg"] = c
        cell["compose_path"] = p

    monkeypatch.setattr("decnet.config.load_state", _fake_load_state)
    monkeypatch.setattr("decnet.config.save_state", _fake_save_state)
    return cell


def test_mutate_success(monkeypatch, tmp_path) -> None:
    cell = _seed_state(monkeypatch, tmp_path)
    compose_calls: list[tuple] = []
    write_compose_calls: list[tuple] = []

    monkeypatch.setattr(
        "decnet.composer.write_compose",
        lambda c, p: write_compose_calls.append((c, p)) or p,
    )
    monkeypatch.setattr(
        "decnet.engine._compose_with_retry",
        lambda *a, **kw: compose_calls.append((a, kw)),
    )

    client = TestClient(app)
    resp = client.post(
        "/mutate",
        json={"decky_id": "decky-01", "services": ["http", "ftp"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body == {"status": "mutated", "decky_id": "decky-01", "services": ["http", "ftp"]}
    assert cell["cfg"].deckies[0].services == ["http", "ftp"]
    assert cell["cfg"].deckies[0].last_mutated > 0
    assert len(write_compose_calls) == 1
    assert len(compose_calls) == 1
    assert compose_calls[0][0] == ("up", "-d", "--remove-orphans")


def test_mutate_unknown_decky_returns_404(monkeypatch, tmp_path) -> None:
    _seed_state(monkeypatch, tmp_path)
    compose_calls: list = []
    monkeypatch.setattr(
        "decnet.engine._compose_with_retry",
        lambda *a, **kw: compose_calls.append((a, kw)),
    )

    client = TestClient(app)
    resp = client.post(
        "/mutate", json={"decky_id": "ghost", "services": ["ssh"]},
    )
    assert resp.status_code == 404
    assert compose_calls == []


def test_mutate_no_state_returns_404(monkeypatch) -> None:
    monkeypatch.setattr("decnet.config.load_state", lambda: None)
    client = TestClient(app)
    resp = client.post(
        "/mutate", json={"decky_id": "decky-01", "services": ["ssh"]},
    )
    assert resp.status_code == 404


def test_mutate_dry_run_does_not_touch_docker_or_state(monkeypatch, tmp_path) -> None:
    cell = _seed_state(monkeypatch, tmp_path)
    saved: list = []
    written: list = []
    composed: list = []

    monkeypatch.setattr(
        "decnet.config.save_state",
        lambda c, p: saved.append((c, p)),
    )
    monkeypatch.setattr(
        "decnet.composer.write_compose",
        lambda c, p: written.append((c, p)),
    )
    monkeypatch.setattr(
        "decnet.engine._compose_with_retry",
        lambda *a, **kw: composed.append((a, kw)),
    )

    original_services = list(cell["cfg"].deckies[0].services)
    client = TestClient(app)
    resp = client.post(
        "/mutate",
        json={"decky_id": "decky-01", "services": ["http"], "dry_run": True},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "dry_run"
    # No persistence, no compose render, no docker.
    assert saved == []
    assert written == []
    assert composed == []
    # State on the in-memory cell was touched (handler mutated the loaded
    # DeckyConfig) but never persisted — load_state is shared by reference,
    # so we only assert that no save/render happened above.
    del original_services


def test_deploy_rejects_malformed_body() -> None:
    client = TestClient(app)
    resp = client.post("/deploy", json={"not": "a config"})
    assert resp.status_code == 422  # pydantic validation


def test_route_set() -> None:
    paths = {r.path for r in app.routes if hasattr(r, "path")}
    assert {"/health", "/status", "/deploy", "/teardown", "/mutate", "/self-destruct"} <= paths


def test_self_destruct_spawns_reaper_and_returns_fast(monkeypatch, tmp_path) -> None:
    """/self-destruct must write the reaper script and spawn it detached
    (start_new_session=True). We intercept Popen so the test doesn't
    actually nuke anything."""
    from decnet.agent import executor as _exec

    spawned: list[dict] = []

    class _FakePopen:
        def __init__(self, args, **kw):
            spawned.append({"args": args, "kw": kw})

    monkeypatch.setattr(_exec, "_deployer", type("X", (), {
        "teardown": staticmethod(lambda _id: None),
    })())
    monkeypatch.setattr(_exec, "clear_state", lambda: None)

    import subprocess as _sp
    monkeypatch.setattr(_sp, "Popen", _FakePopen)

    client = TestClient(app)
    resp = client.post("/self-destruct")
    assert resp.status_code == 200
    assert resp.json()["status"] == "self_destruct_scheduled"
    assert len(spawned) == 1
    assert spawned[0]["kw"].get("start_new_session") is True
    script_candidates = [
        a for a in spawned[0]["args"]
        if isinstance(a, str) and a.startswith("/tmp/decnet-reaper-")
    ]
    assert len(script_candidates) == 1, spawned[0]["args"]
    script_path = script_candidates[0]
    # Reaper content sanity check — covers the paths the operator asked for.
    import pathlib
    body = pathlib.Path(script_path).read_text()
    assert "/opt/decnet*" in body
    assert "/etc/systemd/system/decnet-" in body
    assert "/var/lib/decnet/*" in body
    assert "/usr/local/bin/decnet*" in body
    assert "/etc/decnet" in body
    # Logs must be preserved — no `rm` line should touch /var/log.
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("rm "):
            assert "/var/log" not in stripped
    pathlib.Path(script_path).unlink(missing_ok=True)
