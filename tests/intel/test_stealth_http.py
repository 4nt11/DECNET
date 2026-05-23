# SPDX-License-Identifier: AGPL-3.0-or-later
"""Stealth-egress HTTP client must NOT advertise DECNET.

Captures the request that the client emits (using httpx's MockTransport)
and asserts the User-Agent never contains a DECNET marker. This is the
most important contract on the file — every threat-intel egress path
inherits it.
"""
from __future__ import annotations

import httpx
import pytest

from decnet.net.http import DEFAULT_STEALTH_USER_AGENT, stealth_client


_FORBIDDEN_TOKENS = ("decnet", "honeypot", "decoy", "deck")


@pytest.mark.anyio
async def test_default_user_agent_is_curl_shaped():
    captured: list[httpx.Request] = []

    async def _handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(_handler)
    async with stealth_client() as base:
        # Swap transport to keep test offline.
        base._transport = transport  # noqa: SLF001 — internal field, deliberate
        await base.get("https://api.example.test/check")

    ua = captured[0].headers.get("user-agent", "")
    assert ua == DEFAULT_STEALTH_USER_AGENT
    lower = ua.lower()
    for token in _FORBIDDEN_TOKENS:
        assert token not in lower, f"stealth UA leaked {token!r}: {ua!r}"


@pytest.mark.anyio
async def test_custom_user_agent_override_takes_effect():
    captured: list[httpx.Request] = []

    async def _handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    transport = httpx.MockTransport(_handler)
    async with stealth_client(user_agent="Mozilla/5.0 (test)") as base:
        base._transport = transport  # noqa: SLF001
        await base.get("https://api.example.test/")

    assert captured[0].headers["user-agent"] == "Mozilla/5.0 (test)"


@pytest.mark.anyio
async def test_redirects_do_not_follow_by_default():
    async def _handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://elsewhere/"})

    transport = httpx.MockTransport(_handler)
    async with stealth_client() as base:
        base._transport = transport  # noqa: SLF001
        resp = await base.get("https://api.example.test/")
    assert resp.status_code == 302
