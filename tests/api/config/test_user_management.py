import pytest


@pytest.mark.anyio
async def test_create_user(client, auth_token):
    resp = await client.post(
        "/api/v1/config/users",
        json={"username": "newuser", "password": "securepass123", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "newuser"
    assert data["role"] == "viewer"
    assert data["must_change_password"] is True
    assert "password_hash" not in data


@pytest.mark.anyio
async def test_create_user_duplicate(client, auth_token):
    await client.post(
        "/api/v1/config/users",
        json={"username": "dupuser", "password": "securepass123", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    resp = await client.post(
        "/api/v1/config/users",
        json={"username": "dupuser", "password": "securepass456", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 409


@pytest.mark.anyio
async def test_create_user_viewer_forbidden(client, auth_token, viewer_token):
    resp = await client.post(
        "/api/v1/config/users",
        json={"username": "blocked", "password": "securepass123", "role": "viewer"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_delete_user(client, auth_token):
    # Create a user to delete
    create_resp = await client.post(
        "/api/v1/config/users",
        json={"username": "todelete", "password": "securepass123", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    user_uuid = create_resp.json()["uuid"]

    resp = await client.delete(
        f"/api/v1/config/users/{user_uuid}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200


@pytest.mark.anyio
async def test_delete_self_forbidden(client, auth_token):
    # Get own UUID from config
    config_resp = await client.get(
        "/api/v1/config",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    users = config_resp.json()["users"]
    admin_uuid = next(u["uuid"] for u in users if u["role"] == "admin")

    resp = await client.delete(
        f"/api/v1/config/users/{admin_uuid}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_delete_nonexistent_user(client, auth_token):
    resp = await client.delete(
        "/api/v1/config/users/00000000-0000-0000-0000-000000000000",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_update_user_role(client, auth_token):
    create_resp = await client.post(
        "/api/v1/config/users",
        json={"username": "roletest", "password": "securepass123", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    user_uuid = create_resp.json()["uuid"]

    resp = await client.put(
        f"/api/v1/config/users/{user_uuid}/role",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200

    # Verify role changed
    config_resp = await client.get(
        "/api/v1/config",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    updated = next(u for u in config_resp.json()["users"] if u["uuid"] == user_uuid)
    assert updated["role"] == "admin"


@pytest.mark.anyio
async def test_update_own_role_forbidden(client, auth_token):
    config_resp = await client.get(
        "/api/v1/config",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    admin_uuid = next(u["uuid"] for u in config_resp.json()["users"] if u["role"] == "admin")

    resp = await client.put(
        f"/api/v1/config/users/{admin_uuid}/role",
        json={"role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_reset_user_password(client, auth_token):
    create_resp = await client.post(
        "/api/v1/config/users",
        json={"username": "resetme", "password": "securepass123", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    user_uuid = create_resp.json()["uuid"]

    resp = await client.put(
        f"/api/v1/config/users/{user_uuid}/reset-password",
        json={"new_password": "newpass12345"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200

    # Verify must_change_password is set
    config_resp = await client.get(
        "/api/v1/config",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    updated = next(u for u in config_resp.json()["users"] if u["uuid"] == user_uuid)
    assert updated["must_change_password"] is True

    # Verify new password works
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "resetme", "password": "newpass12345"},
    )
    assert login_resp.status_code == 200


@pytest.mark.anyio
async def test_all_user_endpoints_viewer_forbidden(client, auth_token, viewer_token):
    """Viewer cannot access any user management endpoints."""
    resp = await client.post(
        "/api/v1/config/users",
        json={"username": "x", "password": "securepass123", "role": "viewer"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403

    resp = await client.delete(
        "/api/v1/config/users/fake-uuid",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403

    resp = await client.put(
        "/api/v1/config/users/fake-uuid/role",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403

    resp = await client.put(
        "/api/v1/config/users/fake-uuid/reset-password",
        json={"new_password": "securepass123"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403
