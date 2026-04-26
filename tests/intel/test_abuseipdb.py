"""Unit tests for the AbuseIPDB provider."""
from __future__ import annotations

import json

import httpx
import pytest

from decnet.intel.abuseipdb import AbuseIPDBProvider, _score_to_verdict


def _install_transport(handler) -> list[httpx.Request]:
    captured: list[httpx.Request] = []

    async def _wrapped(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return await handler(request)

    transport = httpx.MockTransport(_wrapped)
    from decnet.intel import abuseipdb as mod

    def _factory():
        return httpx.AsyncClient(
            transport=transport,
            headers={"User-Agent": "curl/7.88.1"},
        )

    mod.stealth_client = _factory  # type: ignore[assignment]
    return captured


def test_score_thresholds():
    assert _score_to_verdict(0) == "benign"
    assert _score_to_verdict(24) == "benign"
    assert _score_to_verdict(25) == "suspicious"
    assert _score_to_verdict(74) == "suspicious"
    assert _score_to_verdict(75) == "malicious"
    assert _score_to_verdict(100) == "malicious"


@pytest.mark.anyio
async def test_missing_api_key_returns_error_no_egress(monkeypatch):
    monkeypatch.delenv("DECNET_ABUSEIPDB_API_KEY", raising=False)
    captured = _install_transport(
        lambda r: (_ for _ in ()).throw(AssertionError("must not egress"))
    )
    provider = AbuseIPDBProvider()
    result = await provider.lookup("1.2.3.4")
    assert result.error == "DECNET_ABUSEIPDB_API_KEY not configured"
    assert result.column_updates == {}
    assert captured == []  # no request made


@pytest.mark.anyio
async def test_high_score_maps_to_malicious(monkeypatch):
    monkeypatch.setenv("DECNET_ABUSEIPDB_API_KEY", "k3y")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {
                "ipAddress": "1.2.3.4",
                "abuseConfidenceScore": 92,
                "totalReports": 41,
                "countryCode": "RU",
            }},
        )

    captured = _install_transport(handler)
    provider = AbuseIPDBProvider()
    result = await provider.lookup("1.2.3.4")
    assert result.verdict == "malicious"
    assert result.column_updates["abuseipdb_score"] == 92
    raw = json.loads(result.column_updates["abuseipdb_raw"])
    assert raw["countryCode"] == "RU"
    # Key header sent, query params correct.
    req = captured[0]
    assert req.headers["key"] == "k3y"
    assert "ipAddress=1.2.3.4" in str(req.url)


@pytest.mark.anyio
async def test_low_score_maps_to_benign(monkeypatch):
    monkeypatch.setenv("DECNET_ABUSEIPDB_API_KEY", "k3y")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"data": {"abuseConfidenceScore": 0}},
        )

    _install_transport(handler)
    provider = AbuseIPDBProvider()
    result = await provider.lookup("8.8.8.8")
    assert result.verdict == "benign"
    assert result.column_updates["abuseipdb_score"] == 0


@pytest.mark.anyio
async def test_429_returns_error(monkeypatch):
    monkeypatch.setenv("DECNET_ABUSEIPDB_API_KEY", "k3y")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429)

    _install_transport(handler)
    provider = AbuseIPDBProvider()
    result = await provider.lookup("1.1.1.1")
    assert result.error == "HTTP 429"
    assert result.column_updates == {}
