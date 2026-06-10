# SPDX-License-Identifier: AGPL-3.0-or-later
import json
import pytest
from hypothesis import given, strategies as st, settings
import httpx
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.limiter import limiter as _limiter
from ..conftest import _FUZZ_SETTINGS

@pytest.mark.anyio
async def test_change_password(client: httpx.AsyncClient) -> None:
    # First login to get token
    login_resp = await client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
    token = login_resp.json()["access_token"]

    # Try changing password with wrong old password
    resp1 = await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": "wrong", "new_password": "new_secure_password"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert resp1.status_code == 401

    # Change password successfully
    resp2 = await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": DECNET_ADMIN_PASSWORD, "new_password": "new_secure_password"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert resp2.status_code == 200

    # Verify old password no longer works
    resp3 = await client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
    assert resp3.status_code == 401

    # Verify new password works and must_change_password is False
    resp4 = await client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": "new_secure_password"})
    assert resp4.status_code == 200
    assert resp4.json()["must_change_password"] is False

@pytest.mark.fuzz
@pytest.mark.anyio
@settings(**_FUZZ_SETTINGS)
@given(
    old_password=st.text(min_size=0, max_size=2048),
    new_password=st.text(min_size=0, max_size=2048)
)
async def test_fuzz_change_password(client: httpx.AsyncClient, old_password: str, new_password: str) -> None:
    """Fuzz the change-password endpoint with random strings."""
    # Get valid token first
    _login_resp: httpx.Response = await client.post("/api/v1/auth/login", json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD})
    _token: str = _login_resp.json()["access_token"]

    _payload: dict[str, str] = {"old_password": old_password, "new_password": new_password}
    try:
        _response: httpx.Response = await client.post(
            "/api/v1/auth/change-password",
            json=_payload,
            headers={"Authorization": f"Bearer {_token}"}
        )
        # 400: schema-guard middleware rejects bad length/shape (e.g. a
        # new_password below the 12-char floor) before the handler runs.
        assert _response.status_code in (200, 400, 401, 422)
    except (UnicodeEncodeError, json.JSONDecodeError):
        pass


# ─── Rate-limit enforcement ─────────────────────────────────────────────────


@pytest.mark.anyio
async def test_change_password_rate_limit_trips_after_5(client: httpx.AsyncClient) -> None:
    """5 change-password attempts from one IP → 6th returns 429."""
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD},
    )
    token = login_resp.json()["access_token"]

    for i in range(5):
        r = await client.post(
            "/api/v1/auth/change-password",
            json={"old_password": f"wrong-{i}", "new_password": "does-not-matter-x!"},
            headers={"Authorization": f"Bearer {token}"},
        )
        # 401 (bad old password) or 429 if the limiter fires — either is fine
        assert r.status_code in (401, 429), f"attempt {i}: got {r.status_code}"

    # The 6th attempt must trip the rate limiter (limit is 5/minute).
    r = await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": "still-wrong", "new_password": "does-not-matter-x!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 429


@pytest.mark.anyio
async def test_change_password_route_has_rate_limit_decorator() -> None:
    """Contract test: change_password handler must be wrapped by slowapi."""
    from decnet.web.router.auth import api_change_pass as _mod

    assert getattr(_mod.change_password, "__wrapped__", None) is not None
