# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bulk session revocation (WI3): password/role changes move tokens_valid_from
forward, killing every prior token for that user.

End-to-end revocation is proven with deterministically *aged* tokens (iat well
in the past) so the assertions don't race the floored-cutoff grey zone — a
token minted in the very same wall-clock second as the change intentionally
survives (see dependencies._resolve_token). The same-second re-login path is
covered separately.
"""
from __future__ import annotations

import time
import uuid as _uuid

import jwt
import pytest
from sqlalchemy import select

from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.auth import ALGORITHM, SECRET_KEY, get_password_hash
from decnet.web.db.models import User
from decnet.web.dependencies import repo

PROTECTED = "/api/v1/attackers?limit=1"


async def _seed_user(username: str, password: str, role: str = "viewer") -> str:
    async with repo.session_factory() as session:
        existing = (await session.execute(
            select(User).where(User.username == username)
        )).scalar_one_or_none()
        if existing:
            return existing.uuid
        u = str(_uuid.uuid4())
        session.add(User(
            uuid=u, username=username, password_hash=get_password_hash(password),
            role=role, must_change_password=False,
        ))
        await session.commit()
        return u


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _uuid_of(token: str) -> str:
    return jwt.decode(token, options={"verify_signature": False})["uuid"]


def _aged_token(uuid: str, *, seconds_old: int = 30) -> str:
    """A well-formed token issued ``seconds_old`` ago — older than any cutoff a
    change sets to 'now', so it is deterministically revoked once bumped."""
    now = int(time.time())
    return jwt.encode(
        {"uuid": uuid, "jti": f"aged-{uuid}", "iat": now - seconds_old, "exp": now + 3600},
        SECRET_KEY, algorithm=ALGORITHM,
    )


async def _login(client, username: str, password: str) -> str:
    r = await client.post(
        "/api/v1/auth/login", json={"username": username, "password": password},
    )
    return r.json()["access_token"]


@pytest.mark.asyncio
async def test_self_password_change_revokes_prior_tokens(client):
    # Dedicated user — the admin fixture already bumped admin's cutoff. The aged
    # token is the "old session"; a fresh login drives the change.
    uuid = await _seed_user("selfchange-user", "selfchange-pass-1")
    aged = _aged_token(uuid)
    assert (await client.get(PROTECTED, headers=_auth(aged))).status_code == 200
    current = await _login(client, "selfchange-user", "selfchange-pass-1")
    r = await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": "selfchange-pass-1", "new_password": "selfchange-pass-2"},
        headers=_auth(current),
    )
    assert r.status_code == 200, r.text
    # Every token issued before the change is dead.
    assert (await client.get(PROTECTED, headers=_auth(aged))).status_code == 401


@pytest.mark.asyncio
async def test_relogin_after_password_change_works_immediately(client, auth_token):
    # Guards the same-second iat/cutoff race: a re-login right after the change
    # must succeed (floored cutoff), not get caught by its own revocation.
    await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": DECNET_ADMIN_PASSWORD, "new_password": "fresh-pass-77"},
        headers=_auth(auth_token),
    )
    fresh = await _login(client, DECNET_ADMIN_USER, "fresh-pass-77")
    assert (await client.get(PROTECTED, headers=_auth(fresh))).status_code == 200


@pytest.mark.asyncio
async def test_admin_password_reset_revokes_target_sessions(client, auth_token, viewer_token):
    viewer_uuid = _uuid_of(viewer_token)
    aged = _aged_token(viewer_uuid)
    assert (await client.get(PROTECTED, headers=_auth(aged))).status_code == 200
    r = await client.put(
        f"/api/v1/config/users/{viewer_uuid}/reset-password",
        json={"new_password": "reset-by-admin-1"},
        headers=_auth(auth_token),
    )
    assert r.status_code == 200, r.text
    assert (await client.get(PROTECTED, headers=_auth(aged))).status_code == 401


@pytest.mark.asyncio
async def test_role_change_revokes_target_sessions(client, auth_token, viewer_token):
    viewer_uuid = _uuid_of(viewer_token)
    aged = _aged_token(viewer_uuid)
    assert (await client.get(PROTECTED, headers=_auth(aged))).status_code == 200
    r = await client.put(
        f"/api/v1/config/users/{viewer_uuid}/role",
        json={"role": "admin"},
        headers=_auth(auth_token),
    )
    assert r.status_code == 200, r.text
    assert (await client.get(PROTECTED, headers=_auth(aged))).status_code == 401


@pytest.mark.asyncio
async def test_revocation_is_per_user(client, auth_token, viewer_token):
    # Resetting the viewer must not revoke the admin's own (valid) token.
    assert (await client.get(PROTECTED, headers=_auth(auth_token))).status_code == 200
    viewer_uuid = _uuid_of(viewer_token)
    await client.put(
        f"/api/v1/config/users/{viewer_uuid}/reset-password",
        json={"new_password": "reset-by-admin-2"},
        headers=_auth(auth_token),
    )
    assert (await client.get(PROTECTED, headers=_auth(auth_token))).status_code == 200
