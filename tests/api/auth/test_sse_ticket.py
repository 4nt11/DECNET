# SPDX-License-Identifier: AGPL-3.0-or-later
"""SSE stream tickets (V3.1.1) + change-password min-length (V2.1.3).

The ticket store is a security boundary: single-use, 60s, fail-closed. These
cover the mint→redeem happy path, single-use reuse rejection, expiry rejection,
the endpoint round-trip, and the V3.1.1 invariant that a raw JWT in the SSE
query string is no longer accepted.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi import HTTPException

from decnet.env import DECNET_ADMIN_USER, DECNET_ADMIN_PASSWORD
from decnet.web.auth import create_access_token
from decnet.web import dependencies as deps


# ── ticket store unit tests ──────────────────────────────────────────────────

def test_mint_then_redeem_happy_path() -> None:
    deps._reset_sse_tickets()
    ticket = deps.mint_sse_ticket("user-1", "viewer")
    identity = deps._redeem_sse_ticket(ticket)
    assert identity == {"uuid": "user-1", "role": "viewer"}


def test_ticket_is_single_use() -> None:
    deps._reset_sse_tickets()
    ticket = deps.mint_sse_ticket("user-1", "admin")
    deps._redeem_sse_ticket(ticket)  # first redeem consumes it
    with pytest.raises(HTTPException) as exc:
        deps._redeem_sse_ticket(ticket)
    assert exc.value.status_code == 401


def test_unknown_ticket_rejected() -> None:
    deps._reset_sse_tickets()
    with pytest.raises(HTTPException) as exc:
        deps._redeem_sse_ticket("never-minted")
    assert exc.value.status_code == 401


def test_expired_ticket_rejected() -> None:
    deps._reset_sse_tickets()
    # Mint, then jam the entry's expiry into the past so redeem fails closed.
    ticket = deps.mint_sse_ticket("user-1", "viewer")
    exp, identity = deps._sse_tickets[ticket]
    deps._sse_tickets[ticket] = (exp - deps._SSE_TICKET_TTL - 1, identity)
    with pytest.raises(HTTPException) as exc:
        deps._redeem_sse_ticket(ticket)
    assert exc.value.status_code == 401


# ── endpoint round-trip ──────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_sse_ticket_endpoint_requires_auth(client: httpx.AsyncClient) -> None:
    resp = await client.post("/api/v1/auth/sse-ticket")
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_sse_ticket_endpoint_mints_and_redeems(
    client: httpx.AsyncClient, auth_token: str
) -> None:
    deps._reset_sse_tickets()
    resp = await client.post(
        "/api/v1/auth/sse-ticket",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["expires_in"] == 60
    ticket = body["ticket"]
    assert ticket and "." not in ticket  # opaque, not a JWT
    # The minted ticket redeems to a bound identity exactly once.
    identity = deps._redeem_sse_ticket(ticket)
    assert "uuid" in identity and identity["role"] in ("admin", "viewer")


def test_raw_jwt_in_sse_query_rejected() -> None:
    """V3.1.1: a raw JWT is not a valid opaque ticket — _redeem_sse_ticket rejects
    any token that wasn't minted by mint_sse_ticket (unknown key → 401)."""
    deps._reset_sse_tickets()
    token = create_access_token({"uuid": "leaked", "jti": "x"})
    with pytest.raises(HTTPException) as exc:
        deps._redeem_sse_ticket(token)
    assert exc.value.status_code == 401


# ── V2.1.3 change-password min length ────────────────────────────────────────

@pytest.mark.anyio
async def test_change_password_below_min_length_rejected(
    client: httpx.AsyncClient,
) -> None:
    resp = await client.post("/api/v1/auth/login", json={
        "username": DECNET_ADMIN_USER, "password": DECNET_ADMIN_PASSWORD,
    })
    token = resp.json()["access_token"]
    # 11 chars — one below the 12-char floor. The request-validation layer
    # rejects the bad length before any auth/logic runs; DECNET's schema-guard
    # middleware surfaces length violations as 400 (not the raw 422).
    r = await client.post(
        "/api/v1/auth/change-password",
        json={"old_password": DECNET_ADMIN_PASSWORD, "new_password": "short123456"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code in (400, 422), r.text
