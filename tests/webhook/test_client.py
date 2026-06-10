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


@pytest.fixture(autouse=True)
def _public_dns(monkeypatch: pytest.MonkeyPatch):
    """Resolve every hostname to a routable public IP so the SSRF guard
    passes for the HMAC/retry behavioral tests without touching the network.

    SSRF-specific tests below override this with their own resolution.
    """
    import socket

    from decnet.webhook import ssrf

    def fake_getaddrinfo(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", fake_getaddrinfo)


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


# ----------------------------- SSRF egress guard ----------------------------


def _resolve_to(monkeypatch, ip: str) -> None:
    import socket as _socket

    from decnet.webhook import ssrf

    def fake(host, port, *a, **k):
        return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (ip, port))]

    monkeypatch.setattr(ssrf.socket, "getaddrinfo", fake)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/inbound",  # loopback literal
        "https://169.254.169.254/latest/meta-data",  # cloud metadata
        "https://10.1.2.3/inbound",  # RFC1918 literal
        "https://192.168.1.5/x",  # RFC1918 literal
        "https://[::1]/x",  # IPv6 loopback
    ],
)
@pytest.mark.asyncio
async def test_deliver_blocks_forbidden_ip_literal(url):
    sent = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        sent["n"] += 1
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await deliver(_sub(url=url), _EVENT, retry_schedule=[], client=client)
    assert result.ok is False
    assert result.attempts == 0  # never left the guard
    assert sent["n"] == 0  # transport never hit


@pytest.mark.asyncio
async def test_deliver_blocks_hostname_resolving_to_private(monkeypatch):
    _resolve_to(monkeypatch, "10.0.0.7")
    sent = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        sent["n"] += 1
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await deliver(
            _sub(url="https://rebind.evil.example/x"), _EVENT,
            retry_schedule=[], client=client,
        )
    assert result.ok is False
    assert sent["n"] == 0
    assert "forbidden" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_deliver_blocks_non_http_scheme():
    result = await deliver(
        _sub(url="file:///etc/passwd"), _EVENT, retry_schedule=[],
    )
    assert result.ok is False
    assert "scheme" in (result.error or "").lower()


@pytest.mark.asyncio
async def test_deliver_public_url_passes(monkeypatch):
    _resolve_to(monkeypatch, "93.184.216.34")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await deliver(
            _sub(url="https://good.example/inbound"), _EVENT,
            retry_schedule=[], client=client,
        )
    assert result.ok is True


@pytest.mark.asyncio
async def test_deliver_allow_private_escape_hatch(monkeypatch):
    # Operator opt-in flips the guard off for internal targets.
    import decnet.env as env

    monkeypatch.setattr(env, "DECNET_WEBHOOK_ALLOW_PRIVATE", True)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        result = await deliver(
            _sub(url="https://127.0.0.1/inbound"), _EVENT,
            retry_schedule=[], client=client,
        )
    assert result.ok is True


@pytest.mark.asyncio
async def test_deliver_does_not_follow_redirect_to_internal(monkeypatch):
    """A 302 pointing at an IMDS address must never be followed.

    deliver() sets follow_redirects=False on every send() call regardless of
    the injected client's config, so the response is the raw 302 and the
    internal IP is never contacted.
    """
    requests_seen: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(str(request.url))
        # First request: public host returns a redirect to the cloud metadata IP.
        return httpx.Response(
            302,
            headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        )

    transport = httpx.MockTransport(handler)
    # Deliberately build the client with follow_redirects=True to prove that
    # deliver() overrides it at the send() level.
    async with httpx.AsyncClient(
        transport=transport, follow_redirects=True
    ) as client:
        result = await deliver(_sub(), _EVENT, retry_schedule=[], client=client)

    # Only the initial request to the public host should have been made.
    assert len(requests_seen) == 1
    assert "169.254.169.254" not in requests_seen[0]
    # deliver() treats the 302 as a non-retryable non-2xx.
    assert result.ok is False
    assert result.status_code == 302
