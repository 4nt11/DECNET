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
    assert {"/health", "/status", "/deploy", "/teardown", "/mutate"} <= paths
