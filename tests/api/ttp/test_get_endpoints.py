"""E.2.8 — GET endpoint shape + auth contract for /api/v1/ttp/*.

Today no TTP router is mounted under :mod:`decnet.web.api`; every
assertion that the documented endpoint exists (200 with a JWT, 401
without) lives behind ``@pytest.mark.xfail(strict=True)`` so this
suite is GREEN today and trips the day E.3.8 wires the router.

The router-presence sanity test is the only assertion that compiles
GREEN today: it asserts that AT LEAST ONE of the documented paths
returns something OTHER than 404 (i.e. the router exists). It is
xfail-strict — when the router lands, the marker flips and the suite
exercises the rest of the contract.
"""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from tests.api.ttp.conftest import (
    BY_ATTACKER,
    BY_CAMPAIGN,
    BY_IDENTITY,
    BY_SESSION,
    NAVIGATOR,
    NAVIGATOR_IDENTITY,
    RULES,
    TECHNIQUES,
    hdr,
)


def _resolve(path: str) -> str:
    """Substitute synthetic UUIDs / IDs into path templates."""
    return path.format(
        identity_uuid="00000000-0000-5000-8000-000000000000",
        attacker_uuid="00000000-0000-5000-8000-000000000001",
        campaign_uuid="00000000-0000-5000-8000-000000000002",
        session_id="sess-deadbeef",
        uuid="00000000-0000-5000-8000-000000000000",
    )


# Documented GET endpoints — each must respond 200 with a JWT and 401
# without. Today they 404 because the router doesn't exist; the
# strict-xfail trip-wire flips when E.3.8 ships.
_GET_ENDPOINTS: list[str] = [
    TECHNIQUES,
    BY_IDENTITY,
    BY_ATTACKER,
    BY_CAMPAIGN,
    BY_SESSION,
    RULES,
    NAVIGATOR,
    NAVIGATOR_IDENTITY,
]


@pytest.mark.parametrize("path", _GET_ENDPOINTS)
@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.8: TTP router not yet mounted",
)
@pytest.mark.asyncio
async def test_get_returns_200_with_jwt(
    client: httpx.AsyncClient, auth_token: str, path: str,
) -> None:
    res = await client.get(_resolve(path), headers=hdr(auth_token))
    assert res.status_code == 200, res.text
    body: Any = res.json()
    # Documented response shapes vary per endpoint; every one is
    # at least a JSON object or list. The schema-stability fixtures
    # under tests/api/ttp/schemas/ pin the per-endpoint shape once
    # impl lands.
    assert isinstance(body, (dict, list))


@pytest.mark.parametrize("path", _GET_ENDPOINTS)
@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.8: TTP router not yet mounted",
)
@pytest.mark.asyncio
async def test_get_returns_401_without_jwt(
    client: httpx.AsyncClient, path: str,
) -> None:
    res = await client.get(_resolve(path))
    # Per project rule: every API GET is auth-gated → 401 without a JWT
    # (NOT 403, NOT 404). Pinned exactly so a future "let unauth read
    # the rules catalogue" change is visible.
    assert res.status_code == 401, (path, res.status_code, res.text)


# ─── Router-presence sanity ──────────────────────────────────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.8: /api/v1/ttp router not yet mounted",
)
@pytest.mark.asyncio
async def test_ttp_router_is_mounted(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    """At least one documented TTP endpoint returns something other
    than 404 — i.e. the router is mounted. The strict-xfail flips
    the day E.3.8 wires the router, regardless of which endpoint
    landed first."""
    res = await client.get(TECHNIQUES, headers=hdr(auth_token))
    assert res.status_code != 404, res.text
