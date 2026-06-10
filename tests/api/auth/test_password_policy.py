# SPDX-License-Identifier: AGPL-3.0-or-later
"""V2.1.4 + V2.1.5 password policy tests.

Covers:
- min_length=12 enforced on CreateUserRequest and ResetUserPasswordRequest
- bcrypt 72-byte limit: multi-byte passwords >72 bytes are rejected (not silently truncated)
"""
import pytest
import httpx
from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD


# '€' (U+20AC) encodes to 3 UTF-8 bytes.
# 25 × 3 = 75 bytes > 72 — valid char count, over the byte cap.
_OVER_72_BYTES: str = "€" * 25

# Exactly at the limit: 24 × 3 = 72 bytes — must be ACCEPTED.
_EXACTLY_72_BYTES: str = "€" * 24


# ─── V2.1.4: min_length=12 on create ────────────────────────────────────────


@pytest.mark.anyio
async def test_create_user_11char_password_rejected(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    """11-character password must be rejected on user creation (min is 12)."""
    resp = await client.post(
        "/api/v1/config/users",
        json={"username": "shortpwduser", "password": "short11char", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Schema-guard middleware may surface as 400; FastAPI validation as 422.
    assert resp.status_code in (400, 422), (
        f"Expected 400/422 for 11-char password on create, got {resp.status_code}"
    )


@pytest.mark.anyio
async def test_create_user_12char_password_accepted(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    """Exactly 12-character ASCII password must be accepted."""
    resp = await client.post(
        "/api/v1/config/users",
        json={"username": "minpwduser12", "password": "exactly12chr", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200, (
        f"Expected 200 for 12-char password on create, got {resp.status_code}: {resp.text}"
    )


# ─── V2.1.4: min_length=12 on reset ─────────────────────────────────────────


@pytest.mark.anyio
async def test_reset_password_11char_rejected(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    """11-character new_password must be rejected on admin password reset."""
    # Create a user to reset
    create_resp = await client.post(
        "/api/v1/config/users",
        json={"username": "resetpolicy1", "password": "securepass123", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert create_resp.status_code == 200
    user_uuid = create_resp.json()["uuid"]

    resp = await client.put(
        f"/api/v1/config/users/{user_uuid}/reset-password",
        json={"new_password": "short11char"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code in (400, 422), (
        f"Expected 400/422 for 11-char password on reset, got {resp.status_code}"
    )


@pytest.mark.anyio
async def test_reset_password_12char_accepted(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    """Exactly 12-character password must be accepted on admin password reset."""
    create_resp = await client.post(
        "/api/v1/config/users",
        json={"username": "resetpolicy2", "password": "securepass123", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert create_resp.status_code == 200
    user_uuid = create_resp.json()["uuid"]

    resp = await client.put(
        f"/api/v1/config/users/{user_uuid}/reset-password",
        json={"new_password": "exactly12chr"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200, (
        f"Expected 200 for 12-char password on reset, got {resp.status_code}: {resp.text}"
    )


# ─── V2.1.5: bcrypt 72-byte rejection on create ─────────────────────────────


@pytest.mark.anyio
async def test_create_user_over_72_bytes_rejected(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    """Password >72 UTF-8 bytes must be rejected on create (bcrypt truncation guard)."""
    resp = await client.post(
        "/api/v1/config/users",
        json={"username": "bytepolicyusr", "password": _OVER_72_BYTES, "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code in (400, 422), (
        f"Expected 400/422 for >{72}-byte password on create, got {resp.status_code}"
    )


@pytest.mark.anyio
async def test_create_user_exactly_72_bytes_accepted(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    """Password of exactly 72 UTF-8 bytes must be accepted (at the limit, not over)."""
    resp = await client.post(
        "/api/v1/config/users",
        json={"username": "byteedgeuser1", "password": _EXACTLY_72_BYTES, "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200, (
        f"Expected 200 for exactly-72-byte password on create, got {resp.status_code}: {resp.text}"
    )


# ─── V2.1.5: bcrypt 72-byte rejection on reset ──────────────────────────────


@pytest.mark.anyio
async def test_reset_password_over_72_bytes_rejected(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    """new_password >72 UTF-8 bytes must be rejected on admin password reset."""
    create_resp = await client.post(
        "/api/v1/config/users",
        json={"username": "byteresetuser", "password": "securepass123", "role": "viewer"},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert create_resp.status_code == 200
    user_uuid = create_resp.json()["uuid"]

    resp = await client.put(
        f"/api/v1/config/users/{user_uuid}/reset-password",
        json={"new_password": _OVER_72_BYTES},
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code in (400, 422), (
        f"Expected 400/422 for >{72}-byte new_password on reset, got {resp.status_code}"
    )


# ─── V2.1.5: bcrypt 72-byte rejection on change-password ────────────────────


@pytest.mark.anyio
async def test_change_password_new_over_72_bytes_rejected(
    client: httpx.AsyncClient,
) -> None:
    """new_password >72 UTF-8 bytes must be rejected on change-password."""
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD},
    )
    token = login_resp.json()["access_token"]

    resp = await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": DECNET_ADMIN_PASSWORD, "new_password": _OVER_72_BYTES},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code in (400, 422), (
        f"Expected 400/422 for >{72}-byte new_password on change-password, got {resp.status_code}"
    )


@pytest.mark.anyio
async def test_change_password_old_over_72_bytes_rejected(
    client: httpx.AsyncClient,
) -> None:
    """old_password >72 UTF-8 bytes must be rejected (no point checking against hash)."""
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD},
    )
    token = login_resp.json()["access_token"]

    resp = await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": _OVER_72_BYTES, "new_password": "new_secure_password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code in (400, 422), (
        f"Expected 400/422 for >{72}-byte old_password on change-password, got {resp.status_code}"
    )
