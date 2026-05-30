# SPDX-License-Identifier: AGPL-3.0-or-later
"""Logout endpoint (WI2): denylists the presented token's jti."""
from __future__ import annotations

import uuid as _uuid

import pytest
from sqlalchemy import select

from decnet.web.auth import get_password_hash
from decnet.web.db.models import User
from decnet.web.dependencies import repo

PROTECTED = "/api/v1/attackers?limit=1"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_logout_revokes_the_presented_token(client, auth_token):
    # Works before logout.
    assert (await client.get(PROTECTED, headers=_auth(auth_token))).status_code == 200
    # Logout succeeds.
    r = await client.post("/api/v1/auth/logout", headers=_auth(auth_token))
    assert r.status_code == 200, r.text
    # The same token is now dead.
    assert (await client.get(PROTECTED, headers=_auth(auth_token))).status_code == 401


@pytest.mark.asyncio
async def test_logout_without_a_token_is_401(client):
    r = await client.post("/api/v1/auth/logout")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_twice_is_rejected(client, auth_token):
    assert (await client.post("/api/v1/auth/logout", headers=_auth(auth_token))).status_code == 200
    # Second attempt with the now-revoked token fails closed.
    assert (await client.post("/api/v1/auth/logout", headers=_auth(auth_token))).status_code == 401


@pytest.mark.asyncio
async def test_logout_only_kills_the_one_session(client, auth_token):
    # A second independent login for the same user keeps working after the
    # first session logs out — single-session, not log-out-everywhere.
    from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
    second = (await client.post(
        "/api/v1/auth/login",
        json={"username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD},
    )).json()["access_token"]

    assert (await client.post("/api/v1/auth/logout", headers=_auth(auth_token))).status_code == 200
    assert (await client.get(PROTECTED, headers=_auth(auth_token))).status_code == 401
    # The other session is untouched.
    assert (await client.get(PROTECTED, headers=_auth(second))).status_code == 200


@pytest.mark.asyncio
async def test_must_change_user_can_still_logout(client):
    # A user with must_change_password=True is blocked from protected routes
    # but must always be able to end their session.
    username, password = "logout-mcp-user", "logout-mcp-pass-1"
    async with repo.session_factory() as session:
        if not (await session.execute(
            select(User).where(User.username == username)
        )).scalar_one_or_none():
            session.add(User(
                uuid=str(_uuid.uuid4()),
                username=username,
                password_hash=get_password_hash(password),
                role="viewer",
                must_change_password=True,
            ))
            await session.commit()

    token = (await client.post(
        "/api/v1/auth/login", json={"username": username, "password": password},
    )).json()["access_token"]
    # Protected route is blocked by must_change...
    assert (await client.get(PROTECTED, headers=_auth(token))).status_code == 403
    # ...but logout still works.
    assert (await client.post("/api/v1/auth/logout", headers=_auth(token))).status_code == 200
    # And the token is revoked afterwards.
    assert (await client.post("/api/v1/auth/logout", headers=_auth(token))).status_code == 401
