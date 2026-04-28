"""Tests for POST /swarm/heartbeat — cert pinning + shard snapshot refresh."""
from __future__ import annotations

import asyncio
import hashlib
import pathlib
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from decnet.web.db.factory import get_repository
from decnet.web.dependencies import get_repo
from decnet.web.router.swarm import api_heartbeat as hb_mod


# ------------------------- shared fixtures (mirror test_swarm_api.py) ---


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


def _enroll(client: TestClient, name: str, address: str = "10.0.0.5") -> dict:
    resp = client.post(
        "/swarm/enroll",
        json={"name": name, "address": address, "agent_port": 8765},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _pin_fingerprint(monkeypatch: pytest.MonkeyPatch, fp: str | None) -> None:
    """Force ``_extract_peer_fingerprint`` to return ``fp`` inside the
    endpoint module so we don't need a live TLS peer."""
    monkeypatch.setattr(hb_mod, "_extract_peer_fingerprint", lambda scope: fp)


def _status_body(deckies: list[dict], runtime: dict[str, dict]) -> dict:
    return {
        "deployed": True,
        "mode": "swarm",
        "compose_path": "/run/decnet/compose.yml",
        "deckies": deckies,
        "runtime": runtime,
    }


def _decky_payload(name: str = "decky-01", ip: str = "10.0.0.50") -> dict:
    return {
        "name": name,
        "hostname": f"{name}.lan",
        "distro": "debian-bookworm",
        "ip": ip,
        "services": ["ssh"],
        "base_image": "debian:bookworm-slim",
        "service_config": {"ssh": {"port": 22}},
        "mutate_interval": 3600,
        "last_mutated": 0.0,
        "archetype": "generic",
        "host_uuid": None,
    }


# ------------------------- _extract_peer_fingerprint unit tests ---------


def test_extract_primary_path_returns_fingerprint() -> None:
    der = b"\x30\x82test-cert-bytes"
    scope = {"extensions": {"tls": {"client_cert_chain": [der]}}}
    assert hb_mod._extract_peer_fingerprint(scope) == hashlib.sha256(der).hexdigest()


def test_extract_fallback_path_when_primary_absent() -> None:
    der = b"\x30\x82fallback-bytes"
    ssl_obj = MagicMock()
    ssl_obj.getpeercert.return_value = der
    transport = MagicMock()
    transport.get_extra_info.return_value = ssl_obj
    scope = {"transport": transport}

    fp = hb_mod._extract_peer_fingerprint(scope)
    assert fp == hashlib.sha256(der).hexdigest()
    transport.get_extra_info.assert_called_with("ssl_object")
    ssl_obj.getpeercert.assert_called_with(binary_form=True)


def test_extract_returns_none_when_both_paths_empty() -> None:
    # No extensions, no transport → fail-closed signal for the endpoint.
    assert hb_mod._extract_peer_fingerprint({}) is None


def test_extract_returns_none_when_transport_ssl_object_missing() -> None:
    transport = MagicMock()
    transport.get_extra_info.return_value = None
    scope = {"transport": transport}
    assert hb_mod._extract_peer_fingerprint(scope) is None


# ------------------------- endpoint behaviour --------------------------


def test_heartbeat_happy_path_primary_extraction(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _enroll(client, "worker-a")
    _pin_fingerprint(monkeypatch, host["fingerprint"])

    body = {
        "host_uuid": host["host_uuid"],
        "agent_version": "1.2.3",
        "status": _status_body(
            [_decky_payload("decky-01")],
            {"decky-01": {"running": True}},
        ),
    }
    resp = client.post("/swarm/heartbeat", json=body)
    assert resp.status_code == 204, resp.text

    async def _verify() -> None:
        row = await repo.get_swarm_host_by_uuid(host["host_uuid"])
        assert row["last_heartbeat"] is not None
        assert row["status"] == "active"
        shards = await repo.list_decky_shards(host["host_uuid"])
        assert len(shards) == 1
        s = shards[0]
        assert s["decky_name"] == "decky-01"
        assert s["decky_ip"] == "10.0.0.50"
        assert s["state"] == "running"
        assert s["last_seen"] is not None
        # snapshot flattening from list_decky_shards
        assert s["hostname"] == "decky-01.lan"
        assert s["archetype"] == "generic"
        assert s["service_config"] == {"ssh": {"port": 22}}

    asyncio.run(_verify())


def test_heartbeat_fallback_extraction_path_also_accepted(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Same endpoint behaviour regardless of which scope path supplied
    # the fingerprint — this guards against uvicorn-version drift where
    # only the fallback slot is populated.
    host = _enroll(client, "worker-b", "10.0.0.6")
    _pin_fingerprint(monkeypatch, host["fingerprint"])

    resp = client.post(
        "/swarm/heartbeat",
        json={
            "host_uuid": host["host_uuid"],
            "status": {"deployed": False, "deckies": []},
        },
    )
    assert resp.status_code == 204


def test_heartbeat_unknown_host_returns_404(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _pin_fingerprint(monkeypatch, "a" * 64)
    resp = client.post(
        "/swarm/heartbeat",
        json={"host_uuid": "does-not-exist", "status": {"deployed": False}},
    )
    assert resp.status_code == 404


def test_heartbeat_fingerprint_mismatch_returns_403(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _enroll(client, "worker-c", "10.0.0.7")
    _pin_fingerprint(monkeypatch, "b" * 64)  # not the host's fingerprint
    resp = client.post(
        "/swarm/heartbeat",
        json={"host_uuid": host["host_uuid"], "status": {"deployed": False}},
    )
    assert resp.status_code == 403
    assert "mismatch" in resp.json()["detail"]


def test_heartbeat_no_peer_cert_fails_closed(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Both extraction paths unavailable → 403, never 200. Fail-closed.
    host = _enroll(client, "worker-d", "10.0.0.8")
    _pin_fingerprint(monkeypatch, None)
    resp = client.post(
        "/swarm/heartbeat",
        json={"host_uuid": host["host_uuid"], "status": {"deployed": False}},
    )
    assert resp.status_code == 403
    assert "unavailable" in resp.json()["detail"]


def test_heartbeat_decommissioned_host_returns_404(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Enrol, capture the fingerprint, delete the host, then replay the
    # heartbeat. Even though the cert is still CA-signed, the decommission
    # revoked the host-row so lookup returns None → 404. Prevents ghost
    # shards from a decommissioned worker.
    host = _enroll(client, "worker-e", "10.0.0.9")
    fp = host["fingerprint"]

    async def _delete() -> None:
        ok = await repo.delete_swarm_host(host["host_uuid"])
        assert ok

    asyncio.run(_delete())

    _pin_fingerprint(monkeypatch, fp)
    resp = client.post(
        "/swarm/heartbeat",
        json={"host_uuid": host["host_uuid"], "status": {"deployed": False}},
    )
    assert resp.status_code == 404


def test_heartbeat_deployed_false_bumps_host_but_writes_no_shards(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _enroll(client, "worker-f", "10.0.0.10")
    _pin_fingerprint(monkeypatch, host["fingerprint"])

    resp = client.post(
        "/swarm/heartbeat",
        json={
            "host_uuid": host["host_uuid"],
            "status": {"deployed": False, "deckies": []},
        },
    )
    assert resp.status_code == 204

    async def _verify() -> None:
        row = await repo.get_swarm_host_by_uuid(host["host_uuid"])
        assert row["last_heartbeat"] is not None
        shards = await repo.list_decky_shards(host["host_uuid"])
        assert shards == []

    asyncio.run(_verify())


def test_heartbeat_decky_missing_from_runtime_is_degraded(
    client: TestClient, repo, monkeypatch: pytest.MonkeyPatch
) -> None:
    host = _enroll(client, "worker-g", "10.0.0.11")
    _pin_fingerprint(monkeypatch, host["fingerprint"])

    body = {
        "host_uuid": host["host_uuid"],
        "status": _status_body(
            [_decky_payload("decky-01"), _decky_payload("decky-02", "10.0.0.51")],
            {"decky-01": {"running": True}},  # decky-02 absent
        ),
    }
    resp = client.post("/swarm/heartbeat", json=body)
    assert resp.status_code == 204

    async def _verify() -> None:
        shards = await repo.list_decky_shards(host["host_uuid"])
        by = {s["decky_name"]: s for s in shards}
        assert by["decky-01"]["state"] == "running"
        assert by["decky-02"]["state"] == "degraded"

    asyncio.run(_verify())
