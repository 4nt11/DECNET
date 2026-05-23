# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for decnet.webhook.client — HMAC + retry policy."""
from __future__ import annotations

import hashlib
import hmac

import httpx
import pytest

from decnet.webhook.client import (
    DeliveryResult,
    SyntheticEvent,
    build_payload,
    deliver,
    sign,
)


_EVENT = SyntheticEvent(
    topic="attacker.observed",
    type="first_sighting",
    ts="2026-04-24T00:00:00+00:00",
    id="11111111-1111-1111-1111-111111111111",
    payload={"ip": "1.2.3.4"},
)


def _sub(url: str = "https://webhook.example/inbound", secret: str = "s" * 32) -> dict:
    return {"uuid": "w1", "url": url, "secret": secret}


def test_sign_matches_known_vector():
    body = b'{"hello":"world"}'
    secret = "0123456789abcdef"
    expected = (
        "sha256="
        + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    )
    assert sign(secret, body) == expected


def test_build_payload_stable_key_order():
    # Same input → same bytes → same HMAC, regardless of kwarg order.
    b1 = build_payload(_EVENT)
    b2 = build_payload(_EVENT)
    assert b1 == b2
    assert b'"topic":"attacker.observed"' in b1
    assert b'"v":1' in b1


@pytest.mark.asyncio
async def test_deliver_success_on_2xx():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("X-DECNET-Signature", "").startswith("sha256=")
        assert request.headers.get("X-DECNET-Event-Id") == _EVENT.id
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await deliver(_sub(), _EVENT, retry_schedule=[], client=client)
    assert result == DeliveryResult(ok=True, status_code=200, attempts=1)


@pytest.mark.asyncio
async def test_deliver_no_retry_on_4xx():
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(400, text="bad body")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await deliver(_sub(), _EVENT, retry_schedule=[1, 1, 1], client=client)
    assert result.ok is False
    assert result.status_code == 400
    assert calls["n"] == 1  # no retry


@pytest.mark.asyncio
async def test_deliver_retries_on_429():
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(429)
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await deliver(_sub(), _EVENT, retry_schedule=[0, 0], client=client)
    assert result.ok is True
    assert result.attempts == 3


@pytest.mark.asyncio
async def test_deliver_retries_on_5xx_then_gives_up():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await deliver(_sub(), _EVENT, retry_schedule=[0, 0], client=client)
    assert result.ok is False
    assert result.status_code == 503
    assert result.attempts == 3


@pytest.mark.asyncio
async def test_deliver_retries_on_connection_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await deliver(_sub(), _EVENT, retry_schedule=[0], client=client)
    assert result.ok is False
    assert result.status_code is None
    assert "ConnectError" in (result.error or "")
    assert result.attempts == 2


@pytest.mark.asyncio
async def test_deliver_receiver_can_verify_signature():
    """End-to-end: receiver recomputes HMAC over the posted body and matches ours."""
    sub = _sub(secret="deadbeefdeadbeef")
    captured: dict = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        captured["sig"] = request.headers["X-DECNET-Signature"]
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await deliver(sub, _EVENT, retry_schedule=[], client=client)
    assert result.ok
    expected = (
        "sha256="
        + hmac.new(
            sub["secret"].encode(), captured["body"], hashlib.sha256
        ).hexdigest()
    )
    assert captured["sig"] == expected
