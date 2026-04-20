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


def test_mutate_is_501() -> None:
    client = TestClient(app)
    resp = client.post("/mutate", json={"decky_id": "decky-01", "services": ["ssh"]})
    assert resp.status_code == 501


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
    script_path = spawned[0]["args"][1]
    assert script_path.startswith("/tmp/decnet-reaper-")
    # Reaper content sanity check — covers the paths the operator asked for.
    import pathlib
    body = pathlib.Path(script_path).read_text()
    assert "/opt/decnet*" in body
    assert "/etc/systemd/system/decnet-" in body
    assert "/var/lib/decnet/*" in body
    assert "/usr/local/bin/decnet*" in body
    # Logs must be preserved — no `rm` line should touch /var/log.
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        if stripped.startswith("rm "):
            assert "/var/log" not in stripped
    pathlib.Path(script_path).unlink(missing_ok=True)
