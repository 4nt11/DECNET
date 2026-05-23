# SPDX-License-Identifier: AGPL-3.0-or-later
"""POST /swarm/heartbeat — lifecycle delta application.

Worker pushes one or more ``lifecycle`` deltas in the heartbeat body
on /deploy or /mutate completion; the master must pivot each delta
onto the matching open DeckyLifecycle row and flip it to terminal.
"""
from __future__ import annotations

import asyncio
import pathlib
from typing import Any

import pytest
from fastapi.testclient import TestClient

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
    r = get_repository(db_path=str(tmp_path / "hb.db"))
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


def _enroll(client: TestClient, name: str = "worker-a") -> dict:
    resp = client.post(
        "/swarm/enroll",
        json={"name": name, "address": "10.0.0.5", "agent_port": 8765},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _pin(monkeypatch: pytest.MonkeyPatch, fp: str | None) -> None:
    monkeypatch.setattr(hb_mod, "_extract_peer_fingerprint", lambda scope: fp)


def _hb_body(host_uuid: str, lifecycle: list[dict] | None = None) -> dict:
    body: dict = {
        "host_uuid": host_uuid,
        "agent_version": "1.0",
        "status": {"deployed": False, "deckies": []},
    }
    if lifecycle is not None:
        body["lifecycle"] = lifecycle
    return body


def test_lifecycle_delta_flips_open_row_to_succeeded(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = _enroll(client)
    _pin(monkeypatch, host["fingerprint"])

    async def _seed_row() -> str:
        return await repo.create_lifecycle({
            "decky_name": "decky-01",
            "host_uuid": host["host_uuid"],
            "operation": "deploy",
            "status": "running",
        })
    lid = asyncio.run(_seed_row())

    resp = client.post("/swarm/heartbeat", json=_hb_body(
        host["host_uuid"],
        lifecycle=[{
            "decky_name": "decky-01",
            "operation": "deploy",
            "status": "succeeded",
        }],
    ))
    assert resp.status_code == 204, resp.text

    async def _verify() -> None:
        rows = await repo.get_lifecycle_by_ids([lid])
        assert rows[0]["status"] == "succeeded"
        assert rows[0]["completed_at"] is not None
    asyncio.run(_verify())


def test_lifecycle_delta_carries_error_on_failure(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = _enroll(client)
    _pin(monkeypatch, host["fingerprint"])

    async def _seed() -> str:
        return await repo.create_lifecycle({
            "decky_name": "decky-01",
            "host_uuid": host["host_uuid"],
            "operation": "mutate",
            "status": "running",
        })
    lid = asyncio.run(_seed())

    resp = client.post("/swarm/heartbeat", json=_hb_body(
        host["host_uuid"],
        lifecycle=[{
            "decky_name": "decky-01",
            "operation": "mutate",
            "status": "failed",
            "error": "compose blew up",
        }],
    ))
    assert resp.status_code == 204

    async def _verify() -> None:
        rows = await repo.get_lifecycle_by_ids([lid])
        assert rows[0]["status"] == "failed"
        assert rows[0]["error"] == "compose blew up"
        assert rows[0]["completed_at"] is not None
    asyncio.run(_verify())


def test_lifecycle_delta_without_open_row_is_silent_noop(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Stale duplicate (e.g. master swept the row out before the delta
    arrived) must not error the heartbeat."""
    host = _enroll(client)
    _pin(monkeypatch, host["fingerprint"])

    resp = client.post("/swarm/heartbeat", json=_hb_body(
        host["host_uuid"],
        lifecycle=[{
            "decky_name": "ghost-decky",
            "operation": "deploy",
            "status": "succeeded",
        }],
    ))
    assert resp.status_code == 204


def test_lifecycle_delta_only_matches_same_host(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A delta from host A must not flip an open row that belongs to host B."""
    host_a = _enroll(client, name="worker-a")
    host_b = _enroll(client, name="worker-b")
    _pin(monkeypatch, host_a["fingerprint"])

    async def _seed() -> str:
        return await repo.create_lifecycle({
            "decky_name": "decky-01",
            "host_uuid": host_b["host_uuid"],
            "operation": "deploy",
            "status": "running",
        })
    lid_b = asyncio.run(_seed())

    resp = client.post("/swarm/heartbeat", json=_hb_body(
        host_a["host_uuid"],
        lifecycle=[{
            "decky_name": "decky-01",
            "operation": "deploy",
            "status": "succeeded",
        }],
    ))
    assert resp.status_code == 204

    async def _verify() -> None:
        rows = await repo.get_lifecycle_by_ids([lid_b])
        assert rows[0]["status"] == "running"  # untouched
    asyncio.run(_verify())


def test_heartbeat_without_lifecycle_field_still_works(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch,
) -> None:
    host = _enroll(client)
    _pin(monkeypatch, host["fingerprint"])
    resp = client.post("/swarm/heartbeat", json=_hb_body(host["host_uuid"]))
    assert resp.status_code == 204
