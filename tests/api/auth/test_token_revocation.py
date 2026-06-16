# SPDX-License-Identifier: AGPL-3.0-or-later
"""JWT revocation foundation (WI1): jti claim, denylist, and bulk cutoff.

These exercise the centralized validate path in decnet.web.dependencies through
real HTTP requests, plus the three repository primitives directly. The wiring
into logout / password-change lives in later work items; here we drive the
mechanism by calling the repo + cache helpers the way those endpoints will.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest

from decnet.web.auth import create_access_token
from decnet.web.dependencies import (
    invalidate_token_cache,
    invalidate_user_cache,
    repo,
)

PROTECTED = "/api/v1/attackers?limit=1"  # auth-gated; 200 for an authed viewer/admin


def _claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------- #
# Token shape                                                                  #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_login_token_carries_jti_and_iat(client, auth_token):
    claims = _claims(auth_token)
    assert claims.get("jti"), "login token must carry a jti for the denylist"
    assert "iat" in claims and "exp" in claims


@pytest.mark.asyncio
async def test_valid_token_is_accepted(client, auth_token):
    r = await client.get(PROTECTED, headers=_auth(auth_token))
    assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- #
# Fail-closed cases                                                            #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_legacy_token_without_jti_is_rejected(client, auth_token):
    # A token minted before this feature (no jti) cannot be revoked, so it is
    # refused outright — one forced re-login on deploy.
    uuid = _claims(auth_token)["uuid"]
    legacy = create_access_token({"uuid": uuid})  # no jti
    r = await client.get(PROTECTED, headers=_auth(legacy))
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_token_for_unknown_user_is_rejected(client):
    ghost = create_access_token({"uuid": "no-such-user", "jti": "ghost"})
    r = await client.get(PROTECTED, headers=_auth(ghost))
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_revoked_jti_is_rejected(client, auth_token):
    claims = _claims(auth_token)
    # Sanity: works before revocation.
    assert (await client.get(PROTECTED, headers=_auth(auth_token))).status_code == 200
    # Denylist this token's jti the way logout will.
    await repo.revoke_token(
        claims["jti"], claims["uuid"],
        datetime.now(timezone.utc) + timedelta(hours=1),
    )
    invalidate_token_cache(claims["jti"])
    r = await client.get(PROTECTED, headers=_auth(auth_token))
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_iat_before_cutoff_is_rejected(client, auth_token):
    claims = _claims(auth_token)
    assert (await client.get(PROTECTED, headers=_auth(auth_token))).status_code == 200
    # Move the bulk cutoff past this token's iat (what password/role change does).
    await repo.set_tokens_valid_from(
        claims["uuid"], datetime.now(timezone.utc) + timedelta(hours=1),
    )
    invalidate_user_cache(claims["uuid"])
    r = await client.get(PROTECTED, headers=_auth(auth_token))
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_token_issued_after_cutoff_still_works(client, auth_token):
    # A cutoff in the PAST must not revoke a token issued now.
    claims = _claims(auth_token)
    await repo.set_tokens_valid_from(
        claims["uuid"], datetime.now(timezone.utc) - timedelta(hours=1),
    )
    invalidate_user_cache(claims["uuid"])
    r = await client.get(PROTECTED, headers=_auth(auth_token))
    assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- #
# Repository primitives                                                        #
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_is_token_revoked_roundtrip(client):
    exp = datetime.now(timezone.utc) + timedelta(hours=1)
    assert await repo.is_token_revoked("jti-a") is False
    await repo.revoke_token("jti-a", "user-1", exp)
    assert await repo.is_token_revoked("jti-a") is True
    # Idempotent — re-revoking the same jti does not raise.
    await repo.revoke_token("jti-a", "user-1", exp)
    assert await repo.is_token_revoked("jti-a") is True


@pytest.mark.asyncio
async def test_revoke_token_prunes_expired_rows(client):
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    await repo.revoke_token("expired-jti", "user-1", past)
    # Inserting a fresh revocation prunes the already-expired row.
    await repo.revoke_token("live-jti", "user-1", future)
    assert await repo.is_token_revoked("expired-jti") is False
    assert await repo.is_token_revoked("live-jti") is True


@pytest.mark.asyncio
async def test_set_tokens_valid_from_persists(client, auth_token):
    uuid = _claims(auth_token)["uuid"]
    ts = datetime.now(timezone.utc)
    await repo.set_tokens_valid_from(uuid, ts)
    user = await repo.get_user_by_uuid(uuid)
    assert user is not None and user["tokens_valid_from"] is not None
