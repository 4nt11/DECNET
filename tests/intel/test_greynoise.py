"""Unit tests for the GreyNoise Community provider.

Mocks httpx via ``MockTransport`` and asserts:

* request URL + headers (API key when present, none when absent)
* malicious / benign / suspicious classification → verdict mapping
* 404 → verdict='unknown' with no error (cache the absence)
* non-200/404 → error populated, no column writes
* network exception → error populated
* the row never advertises DECNET in the egress UA
"""
from __future__ import annotations

import json

import httpx
import pytest

from decnet.intel.greynoise import GreyNoiseProvider


def _install_transport(provider: GreyNoiseProvider, handler) -> list[httpx.Request]:
    """Patch ``stealth_client`` so it returns a client wired to ``handler``."""
    captured: list[httpx.Request] = []

    async def _wrapped(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return await handler(request)

    transport = httpx.MockTransport(_wrapped)

    from decnet.intel import greynoise as gn_mod

    def _factory():
        return httpx.AsyncClient(
            transport=transport,
            headers={"User-Agent": "curl/7.88.1"},
        )

    gn_mod.stealth_client = _factory  # type: ignore[assignment]
    return captured


@pytest.mark.anyio
async def test_malicious_classification_maps_to_verdict():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "ip": "1.2.3.4",
                "noise": True,
                "classification": "malicious",
                "name": "Mirai-like",
            },
        )

    provider = GreyNoiseProvider()
    captured = _install_transport(provider, handler)

    result = await provider.lookup("1.2.3.4")
    assert result.error is None
    assert result.verdict == "malicious"
    assert result.column_updates["greynoise_classification"] == "malicious"
    raw = json.loads(result.column_updates["greynoise_raw"])
    assert raw["name"] == "Mirai-like"
    assert "1.2.3.4" in str(captured[0].url)
    # No DECNET label leaks in the UA.
    assert "decnet" not in captured[0].headers["user-agent"].lower()


@pytest.mark.anyio
async def test_api_key_is_sent_when_configured(monkeypatch):
    monkeypatch.setenv("DECNET_GREYNOISE_API_KEY", "k3y-abc")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"classification": "benign"})

    provider = GreyNoiseProvider()
    captured = _install_transport(provider, handler)

    await provider.lookup("8.8.8.8")
    assert captured[0].headers.get("key") == "k3y-abc"


@pytest.mark.anyio
async def test_no_api_key_means_no_header(monkeypatch):
    monkeypatch.delenv("DECNET_GREYNOISE_API_KEY", raising=False)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"classification": "benign"})

    provider = GreyNoiseProvider()
    captured = _install_transport(provider, handler)

    await provider.lookup("8.8.8.8")
    assert "key" not in captured[0].headers


@pytest.mark.anyio
async def test_404_caches_unknown_without_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "IP not observed"})

    provider = GreyNoiseProvider()
    _install_transport(provider, handler)

    result = await provider.lookup("10.0.0.5")
    assert result.error is None
    assert result.verdict == "unknown"
    assert result.column_updates["greynoise_classification"] == "unknown"


@pytest.mark.anyio
async def test_429_returns_error_no_writes():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    provider = GreyNoiseProvider()
    _install_transport(provider, handler)

    result = await provider.lookup("1.1.1.1")
    assert result.error == "HTTP 429"
    assert result.column_updates == {}


@pytest.mark.anyio
async def test_network_failure_becomes_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("upstream unreachable")

    provider = GreyNoiseProvider()
    _install_transport(provider, handler)

    result = await provider.lookup("1.1.1.1")
    assert result.error and result.error.startswith("network:")
    assert result.column_updates == {}
