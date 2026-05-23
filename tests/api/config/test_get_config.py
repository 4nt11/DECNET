# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest


@pytest.mark.anyio
async def test_get_config_defaults_admin(client, auth_token):
    """Admin gets full config with users list and defaults."""
    resp = await client.get(
        "/api/v1/config",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "admin"
    assert data["deployment_limit"] == 10
    assert data["global_mutation_interval"] == "30m"
    assert "users" in data
    assert isinstance(data["users"], list)
    assert len(data["users"]) >= 1
    # Ensure no password_hash leaked
    for user in data["users"]:
        assert "password_hash" not in user
        assert "uuid" in user
        assert "username" in user
        assert "role" in user


@pytest.mark.anyio
async def test_get_config_viewer_no_users(client, auth_token, viewer_token):
    """Viewer gets config without users list — server-side gating."""
    resp = await client.get(
        "/api/v1/config",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "viewer"
    assert data["deployment_limit"] == 10
    assert data["global_mutation_interval"] == "30m"
    assert "users" not in data


@pytest.mark.anyio
async def test_get_config_returns_stored_values(client, auth_token):
    """Config returns stored values after update."""
    await client.put(
        "/api/v1/config/deployment-limit",
        json={"deployment_limit": 42},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    await client.put(
        "/api/v1/config/global-mutation-interval",
        json={"global_mutation_interval": "7d"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )

    resp = await client.get(
        "/api/v1/config",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["deployment_limit"] == 42
    assert data["global_mutation_interval"] == "7d"


@pytest.mark.anyio
async def test_get_config_unauthenticated(client):
    resp = await client.get("/api/v1/config")
    assert resp.status_code == 401
