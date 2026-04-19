"""POST /api/v1/swarm-updates/rollback — single-host manual rollback."""
from __future__ import annotations

import pytest


@pytest.mark.anyio
async def test_rollback_happy_path(client, auth_token, add_host, fake_updater):
    h = await add_host("alpha")

    resp = await client.post(
        "/api/v1/swarm-updates/rollback",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"host_uuid": h["uuid"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "rolled-back"
    assert body["host_name"] == "alpha"


@pytest.mark.anyio
async def test_rollback_404_when_no_previous(client, auth_token, add_host, fake_updater):
    h = await add_host("alpha")
    Resp = fake_updater["Response"]
    fake_updater["client"].rollback_responses = {
        "alpha": Resp(404, {"detail": "no previous release"}),
    }

    resp = await client.post(
        "/api/v1/swarm-updates/rollback",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"host_uuid": h["uuid"]},
    )
    assert resp.status_code == 404
    assert "no previous" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_rollback_transport_failure_reported(client, auth_token, add_host, fake_updater):
    h = await add_host("alpha")
    fake_updater["client"].rollback_responses = {"alpha": RuntimeError("TLS handshake failed")}

    resp = await client.post(
        "/api/v1/swarm-updates/rollback",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"host_uuid": h["uuid"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failed"
    assert "TLS handshake" in body["detail"]


@pytest.mark.anyio
async def test_rollback_unknown_host(client, auth_token, fake_updater):
    resp = await client.post(
        "/api/v1/swarm-updates/rollback",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"host_uuid": "nonexistent"},
    )
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_rollback_on_agent_only_host_rejected(
    client, auth_token, add_host, fake_updater,
):
    h = await add_host("alpha", with_updater=False)
    resp = await client.post(
        "/api/v1/swarm-updates/rollback",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"host_uuid": h["uuid"]},
    )
    assert resp.status_code == 400


@pytest.mark.anyio
async def test_viewer_is_forbidden(client, viewer_token, add_host, fake_updater):
    h = await add_host("alpha")
    resp = await client.post(
        "/api/v1/swarm-updates/rollback",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"host_uuid": h["uuid"]},
    )
    assert resp.status_code == 403
