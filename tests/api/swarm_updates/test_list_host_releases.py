"""GET /api/v1/swarm-updates/hosts — per-host updater health fan-out."""
from __future__ import annotations

import pytest


@pytest.mark.anyio
async def test_admin_lists_reachable_and_unreachable_hosts(
    client, auth_token, add_host, fake_updater,
):
    await add_host("alpha", "10.0.0.1")
    await add_host("beta", "10.0.0.2")

    fake_updater["client"].health_responses = {
        "alpha": {
            "status": "ok",
            "agent_status": "ok",
            "releases": [
                {"slot": "active", "sha": "aaaa111", "healthy": True},
                {"slot": "prev", "sha": "0000000", "healthy": True},
            ],
        },
        "beta": RuntimeError("TLS handshake failed"),
    }

    resp = await client.get(
        "/api/v1/swarm-updates/hosts",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    hosts = {h["host_name"]: h for h in resp.json()["hosts"]}
    assert hosts["alpha"]["reachable"] is True
    assert hosts["alpha"]["current_sha"] == "aaaa111"
    assert hosts["alpha"]["previous_sha"] == "0000000"
    assert hosts["beta"]["reachable"] is False
    assert "TLS handshake" in hosts["beta"]["detail"]


@pytest.mark.anyio
async def test_decommissioned_and_agent_only_hosts_are_excluded(
    client, auth_token, add_host, fake_updater,
):
    await add_host("good", "10.0.0.1", with_updater=True)
    await add_host("gone", "10.0.0.2", with_updater=True, status="decommissioned")
    await add_host("agentonly", "10.0.0.3", with_updater=False)

    resp = await client.get(
        "/api/v1/swarm-updates/hosts",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    names = {h["host_name"] for h in resp.json()["hosts"]}
    assert names == {"good"}


@pytest.mark.anyio
async def test_viewer_is_forbidden(client, viewer_token, add_host, fake_updater):
    await add_host("alpha")
    resp = await client.get(
        "/api/v1/swarm-updates/hosts",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_unauth_returns_401(client):
    resp = await client.get("/api/v1/swarm-updates/hosts")
    assert resp.status_code == 401
