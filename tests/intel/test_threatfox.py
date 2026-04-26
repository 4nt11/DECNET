"""Unit tests for the abuse.ch ThreatFox provider."""
from __future__ import annotations

import json

import httpx
import pytest

from decnet.intel.threatfox import ThreatFoxProvider


def _install_transport(handler) -> list[httpx.Request]:
    captured: list[httpx.Request] = []

    async def _wrapped(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return await handler(request)

    transport = httpx.MockTransport(_wrapped)
    from decnet.intel import threatfox as mod

    def _factory():
        return httpx.AsyncClient(
            transport=transport,
            headers={"User-Agent": "curl/7.88.1"},
        )

    mod.stealth_client = _factory  # type: ignore[assignment]
    return captured


@pytest.mark.anyio
async def test_match_returns_malicious(monkeypatch):
    monkeypatch.delenv("DECNET_THREATFOX_API_KEY", raising=False)

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        assert body == {"query": "search_ioc", "search_term": "1.2.3.4"}
        return httpx.Response(
            200,
            json={
                "query_status": "ok",
                "data": [
                    {
                        "ioc": "1.2.3.4",
                        "ioc_type": "ip:port",
                        "malware": "Cobalt Strike",
                        "confidence_level": 80,
                    }
                ],
            },
        )

    captured = _install_transport(handler)
    provider = ThreatFoxProvider()
    result = await provider.lookup("1.2.3.4")
    assert result.verdict == "malicious"
    assert result.column_updates["threatfox_listed"] is True
    raw = json.loads(result.column_updates["threatfox_raw"])
    assert raw[0]["malware"] == "Cobalt Strike"
    # No Auth-Key when none configured.
    assert "auth-key" not in {h.lower() for h in captured[0].headers}


@pytest.mark.anyio
async def test_auth_key_sent_when_configured(monkeypatch):
    monkeypatch.setenv("DECNET_THREATFOX_API_KEY", "tfx-key")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "no_result"})

    captured = _install_transport(handler)
    provider = ThreatFoxProvider()
    await provider.lookup("8.8.8.8")
    assert captured[0].headers["auth-key"] == "tfx-key"


@pytest.mark.anyio
async def test_no_result_caches_unlisted():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "no_result"})

    _install_transport(handler)
    provider = ThreatFoxProvider()
    result = await provider.lookup("8.8.8.8")
    assert result.verdict is None
    assert result.column_updates["threatfox_listed"] is False
    assert result.error is None


@pytest.mark.anyio
async def test_unexpected_status_is_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"query_status": "illegal_search"})

    _install_transport(handler)
    provider = ThreatFoxProvider()
    result = await provider.lookup("oops")
    assert result.error and "illegal_search" in result.error
    assert result.column_updates == {}


@pytest.mark.anyio
async def test_http_error_surfaces():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502)

    _install_transport(handler)
    provider = ThreatFoxProvider()
    result = await provider.lookup("1.1.1.1")
    assert result.error == "HTTP 502"
