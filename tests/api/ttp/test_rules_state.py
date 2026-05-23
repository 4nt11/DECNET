# SPDX-License-Identifier: AGPL-3.0-or-later
"""E.2.8 — Admin-only mutation endpoints for /api/v1/ttp/rules/{id}/state.

The two mutation endpoints (POST / DELETE) carry the rule
disable/clip/TTL knobs. Per the project's "no client-side role
checks" rule, the assertions here all hit the server and inspect
the response — never a feature flag, never a route table.

The router landed at E.1.9 with the admin guard on POST/DELETE; the
assertions exercise the auth + body-validation contract directly.
Persistence (state actually surviving a roundtrip) lands in E.3.
"""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from tests.api.ttp.conftest import RULE_STATE, hdr


_RULE_ID = "R0001"
_VALID_BODY: dict[str, Any] = {"state": "disabled"}


def _path() -> str:
    return RULE_STATE.format(rule_id=_RULE_ID)


# ─── POST /rules/{rule_id}/state ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_post_state_without_jwt_is_401(
    client: httpx.AsyncClient,
) -> None:
    res = await client.post(_path(), json=_VALID_BODY)
    assert res.status_code == 401, res.text


@pytest.mark.asyncio
async def test_post_state_non_admin_is_403_server_side(
    client: httpx.AsyncClient, viewer_token: str,
) -> None:
    """SERVER-SIDE enforcement — the test inspects the server's
    response, not a client-side role check. A regression that drops
    the role gate to client-only logic is caught here even when the
    UI hides the button."""
    res = await client.post(
        _path(), json=_VALID_BODY, headers=hdr(viewer_token),
    )
    assert res.status_code == 403, res.text


@pytest.mark.asyncio
async def test_post_state_admin_is_200(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    res = await client.post(
        _path(), json=_VALID_BODY, headers=hdr(auth_token),
    )
    assert res.status_code == 200, res.text


@pytest.mark.asyncio
async def test_post_state_malformed_body_is_400(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    """Per the project's "POST/PUT/PATCH 400 documented" convention:
    a body that fails Starlette's JSON parse must surface as a
    documented 400, not a 422 or a 500."""
    res = await client.post(
        _path(),
        content=b"this is not json",
        headers={
            **hdr(auth_token),
            "content-type": "application/json",
        },
    )
    assert res.status_code == 400, res.text


# ─── DELETE /rules/{rule_id}/state ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_state_without_jwt_is_401(
    client: httpx.AsyncClient,
) -> None:
    res = await client.delete(_path())
    assert res.status_code == 401, res.text


@pytest.mark.asyncio
async def test_delete_state_non_admin_is_403_server_side(
    client: httpx.AsyncClient, viewer_token: str,
) -> None:
    res = await client.delete(_path(), headers=hdr(viewer_token))
    assert res.status_code == 403, res.text


@pytest.mark.asyncio
async def test_delete_state_admin_is_204_or_200(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    """The spec allows either 204 (preferred — no content) or 200
    for the DELETE → revert-to-default semantics. Pinned as a small
    set so impl can choose without rewriting the test."""
    res = await client.delete(_path(), headers=hdr(auth_token))
    assert res.status_code in (200, 204), res.text
