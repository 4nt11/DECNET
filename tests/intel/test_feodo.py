"""Unit tests for the abuse.ch Feodo Tracker provider.

Bulk-feed semantics: one HTTP fetch loads the in-memory set, all
subsequent ``lookup`` calls hit memory. We assert:

* a fresh provider triggers exactly one refresh, then answers from cache
* a listed IP returns verdict='malicious' with the upstream record
* an unlisted IP returns verdict=None (absence ≠ benign)
* a feed fetch failure is reported as an error, not silently swallowed
"""
from __future__ import annotations


import httpx
import pytest

from decnet.intel.feodo import FeodoProvider


def _install_transport(handler) -> list[httpx.Request]:
    captured: list[httpx.Request] = []

    async def _wrapped(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return await handler(request)

    transport = httpx.MockTransport(_wrapped)
    from decnet.intel import feodo as mod

    def _factory(*, timeout: float = 20.0):
        return httpx.AsyncClient(
            transport=transport,
            headers={"User-Agent": "curl/7.88.1"},
            timeout=timeout,
        )

    mod.stealth_client = _factory  # type: ignore[assignment]
    return captured


_FEED = [
    {"ip_address": "9.9.9.9", "port": 443, "malware": "TrickBot"},
    {"ip_address": "10.10.10.10", "port": 80, "malware": "Emotet"},
]


@pytest.mark.anyio
async def test_listed_ip_yields_malicious_verdict():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_FEED)

    captured = _install_transport(handler)
    provider = FeodoProvider(refresh_interval_s=999.0)

    result = await provider.lookup("9.9.9.9")
    assert result.verdict == "malicious"
    assert result.column_updates["feodo_listed"] is True
    assert result.column_updates["feodo_raw"]["malware"] == "TrickBot"
    assert len(captured) == 1


@pytest.mark.anyio
async def test_subsequent_lookups_dont_refetch():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_FEED)

    captured = _install_transport(handler)
    provider = FeodoProvider(refresh_interval_s=999.0)

    await provider.lookup("9.9.9.9")
    await provider.lookup("10.10.10.10")
    await provider.lookup("not-listed.example")
    assert len(captured) == 1  # one refresh, three answers


@pytest.mark.anyio
async def test_unlisted_ip_returns_no_verdict():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_FEED)

    _install_transport(handler)
    provider = FeodoProvider(refresh_interval_s=999.0)
    result = await provider.lookup("1.2.3.4")
    assert result.verdict is None
    assert result.column_updates["feodo_listed"] is False


@pytest.mark.anyio
async def test_listed_ip_persists_malware_family():
    """Post-2026-05-02 audit: IntelLifter reads
    ``feodo_malware_family`` for evidence; persist it as a typed
    column rather than only inside ``feodo_raw``."""
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_FEED)

    _install_transport(handler)
    provider = FeodoProvider(refresh_interval_s=999.0)
    result = await provider.lookup("9.9.9.9")
    assert result.column_updates["feodo_malware_family"] == "TrickBot"


@pytest.mark.anyio
async def test_unlisted_ip_clears_family():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_FEED)

    _install_transport(handler)
    provider = FeodoProvider(refresh_interval_s=999.0)
    result = await provider.lookup("1.2.3.4")
    assert result.column_updates["feodo_malware_family"] is None


@pytest.mark.anyio
async def test_feed_failure_reports_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    _install_transport(handler)
    provider = FeodoProvider(refresh_interval_s=999.0)
    result = await provider.lookup("1.2.3.4")
    assert result.error == "HTTP 503"
    assert result.column_updates == {}
