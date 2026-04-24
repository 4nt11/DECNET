"""XFF / proxy-family mismatch detection in the ingester's bounty extractor."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from decnet.web.ingester import _detect_ip_leak, _extract_bounty


def _log_row(
    headers: dict[str, str] | None = None,
    *,
    source_ip: str = "203.0.113.42",
    service: str = "http",
    event_type: str = "request",
) -> dict:
    return {
        "decky": "http-01",
        "service": service,
        "attacker_ip": source_ip,
        "event_type": event_type,
        "fields": {
            "method": "GET",
            "path": "/wp-admin/",
            "headers": headers or {},
        },
    }


# ─── pure detector ──────────────────────────────────────────────────────────

def test_xff_leftmost_differs_from_source_emits_leak():
    row = _log_row({
        "X-Forwarded-For": "198.51.100.7, 10.0.0.1",
    })
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["source_ip"] == "203.0.113.42"
    assert result["real_ip_claim"] == "198.51.100.7"
    assert result["source_header"] == "X-Forwarded-For"
    assert result["path"] == "/wp-admin/"


def test_xff_matches_source_no_leak():
    row = _log_row({"X-Forwarded-For": "203.0.113.42"})
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_forwarded_header_rfc7239_parsed():
    row = _log_row({"Forwarded": "for=1.2.3.4;by=5.6.7.8"})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["real_ip_claim"] == "1.2.3.4"
    assert result["source_header"] == "Forwarded"


def test_forwarded_with_ipv6_and_port():
    row = _log_row({"Forwarded": 'for="[2001:db8::1]:4711"'})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["real_ip_claim"] == "2001:db8::1"


def test_x_real_ip_fallback():
    row = _log_row({"X-Real-IP": "198.51.100.7"})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["source_header"] == "X-Real-IP"
    assert result["real_ip_claim"] == "198.51.100.7"


def test_cf_connecting_ip_variant():
    row = _log_row({"CF-Connecting-IP": "198.51.100.9"})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["source_header"] == "CF-Connecting-IP"
    assert result["real_ip_claim"] == "198.51.100.9"


def test_priority_forwarded_over_xff():
    row = _log_row({
        "Forwarded": "for=1.1.1.1",
        "X-Forwarded-For": "2.2.2.2",
        "X-Real-IP": "3.3.3.3",
    })
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["source_header"] == "Forwarded"
    assert result["real_ip_claim"] == "1.1.1.1"
    # All proxy headers preserved in metadata.
    assert "X-Forwarded-For" in result["headers_seen"]
    assert "X-Real-IP" in result["headers_seen"]


def test_case_insensitive_header_match():
    row = _log_row({"x-forwarded-for": "198.51.100.7"})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["real_ip_claim"] == "198.51.100.7"


def test_trusted_proxy_source_skipped(monkeypatch):
    monkeypatch.setenv("DECNET_TRUSTED_PROXIES", "203.0.113.42")
    row = _log_row({"X-Forwarded-For": "198.51.100.7"})
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_trusted_proxy_cidr(monkeypatch):
    monkeypatch.setenv("DECNET_TRUSTED_PROXIES", "203.0.113.0/24")
    row = _log_row({"X-Forwarded-For": "198.51.100.7"})
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_malformed_xff_falls_through_to_next_parseable():
    row = _log_row({"X-Forwarded-For": "garbage, 198.51.100.7, not-ip"})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["real_ip_claim"] == "198.51.100.7"


def test_all_values_unparseable_bails():
    row = _log_row({"X-Forwarded-For": "not-ip, still-not-ip"})
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_no_headers_skipped():
    row = _log_row({})
    assert _detect_ip_leak(row, {}) is None


def test_non_http_service_skipped():
    row = _log_row(
        {"X-Forwarded-For": "198.51.100.7"},
        service="ssh",
    )
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_missing_attacker_ip_bails():
    row = _log_row({"X-Forwarded-For": "198.51.100.7"}, source_ip="")
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


# ─── end-to-end via _extract_bounty ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_extract_bounty_emits_ip_leak_row():
    row = _log_row({
        "X-Forwarded-For": "198.51.100.7",
        "User-Agent": "curl/7.81.0",
    })
    repo = AsyncMock()
    await _extract_bounty(repo, row)

    # Expect two bounty calls — User-Agent fingerprint + ip_leak.
    types = [
        call.args[0]["bounty_type"]
        for call in repo.add_bounty.call_args_list
    ]
    assert "fingerprint" in types
    assert "ip_leak" in types

    leak_call = next(
        c for c in repo.add_bounty.call_args_list
        if c.args[0]["bounty_type"] == "ip_leak"
    )
    payload = leak_call.args[0]["payload"]
    assert payload["real_ip_claim"] == "198.51.100.7"
    assert payload["source_ip"] == "203.0.113.42"


@pytest.mark.asyncio
async def test_extract_bounty_no_leak_no_call():
    row = _log_row({"X-Forwarded-For": "203.0.113.42"})  # matches source
    repo = AsyncMock()
    await _extract_bounty(repo, row)

    types = [
        call.args[0]["bounty_type"]
        for call in repo.add_bounty.call_args_list
    ]
    assert "ip_leak" not in types
