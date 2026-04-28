"""RBAC matrix tests — verify role enforcement on every API endpoint."""
import pytest


# ── Read-only endpoints: viewer + admin should both get access ──────────

_VIEWER_ENDPOINTS = [
    ("GET", "/api/v1/logs"),
    ("GET", "/api/v1/logs/histogram"),
    ("GET", "/api/v1/bounty"),
    ("GET", "/api/v1/deckies"),
    ("GET", "/api/v1/stats"),
    ("GET", "/api/v1/attackers"),
    ("GET", "/api/v1/config"),
]


@pytest.mark.anyio
@pytest.mark.parametrize("method,path", _VIEWER_ENDPOINTS)
async def test_viewer_can_access_read_endpoints(client, viewer_token, method, path):
    resp = await client.request(
        method, path, headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert resp.status_code == 200, f"{method} {path} returned {resp.status_code}"


@pytest.mark.anyio
@pytest.mark.parametrize("method,path", _VIEWER_ENDPOINTS)
async def test_admin_can_access_read_endpoints(client, auth_token, method, path):
    resp = await client.request(
        method, path, headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert resp.status_code == 200, f"{method} {path} returned {resp.status_code}"


# ── Admin-only endpoints: viewer must get 403 ──────────────────────────

_ADMIN_ENDPOINTS = [
    ("PUT", "/api/v1/config/deployment-limit", {"deployment_limit": 5}),
    ("PUT", "/api/v1/config/global-mutation-interval", {"global_mutation_interval": "1d"}),
    ("POST", "/api/v1/config/users", {"username": "rbac-test", "password": "pass123456", "role": "viewer"}),
]


@pytest.mark.anyio
@pytest.mark.parametrize("method,path,body", _ADMIN_ENDPOINTS)
async def test_viewer_blocked_from_admin_endpoints(client, viewer_token, method, path, body):
    resp = await client.request(
        method, path,
        json=body,
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403, f"{method} {path} returned {resp.status_code}"


@pytest.mark.anyio
@pytest.mark.parametrize("method,path,body", _ADMIN_ENDPOINTS)
async def test_admin_can_access_admin_endpoints(client, auth_token, method, path, body):
    resp = await client.request(
        method, path,
        json=body,
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200, f"{method} {path} returned {resp.status_code}"


# ── Unauthenticated access: must get 401 ───────────────────────────────

_ALL_PROTECTED = [
    ("GET", "/api/v1/logs"),
    ("GET", "/api/v1/stats"),
    ("GET", "/api/v1/deckies"),
    ("GET", "/api/v1/bounty"),
    ("GET", "/api/v1/attackers"),
    ("GET", "/api/v1/config"),
    ("PUT", "/api/v1/config/deployment-limit"),
    ("POST", "/api/v1/config/users"),
]


@pytest.mark.anyio
@pytest.mark.parametrize("method,path", _ALL_PROTECTED)
async def test_unauthenticated_returns_401(client, method, path):
    resp = await client.request(method, path)
    assert resp.status_code == 401, f"{method} {path} returned {resp.status_code}"


# ── Fleet write endpoints: viewer must get 403 ─────────────────────────

@pytest.mark.anyio
async def test_viewer_blocked_from_deploy(client, viewer_token):
    resp = await client.post(
        "/api/v1/deckies/deploy",
        json={"ini_content": "[decky-rbac-test]\nservices=ssh"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_viewer_blocked_from_mutate(client, viewer_token):
    resp = await client.post(
        "/api/v1/deckies/test-decky/mutate",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.anyio
async def test_viewer_blocked_from_mutate_interval(client, viewer_token):
    resp = await client.put(
        "/api/v1/deckies/test-decky/mutate-interval",
        json={"mutate_interval": "5d"},
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403
