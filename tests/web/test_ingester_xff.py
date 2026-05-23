# SPDX-License-Identifier: AGPL-3.0-or-later
"""XFF / proxy-family mismatch detection in the ingester's bounty extractor."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from decnet.web.ingester import (
    _categorize_claimed_ip,
    _detect_ip_leak,
    _detect_spoofed_source,
    _extract_bounty,
)


def _log_row(
    headers: dict[str, str] | None = None,
    *,
    source_ip: str = "8.8.8.8",
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
        "X-Forwarded-For": "1.1.1.1, 10.0.0.1",
    })
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["source_ip"] == "8.8.8.8"
    assert result["real_ip_claim"] == "1.1.1.1"
    assert result["source_header"] == "X-Forwarded-For"
    # Identity-only payload — method/path intentionally omitted so the
    # bounty dedup collapses repeat hits from the same attacker.
    assert "method" not in result
    assert "path" not in result


def test_xff_matches_source_no_leak():
    row = _log_row({"X-Forwarded-For": "8.8.8.8"})
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_xff_loopback_is_not_a_leak():
    """curl -H 'X-Forwarded-For: 127.0.0.1' is the classic WAF-bypass
    payload. Must not be classified as an attribution leak — loopback
    is not a routable IP anyone could actually have as their real
    address."""
    row = _log_row({"X-Forwarded-For": "127.0.0.1"})
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_xff_rfc1918_is_not_a_leak():
    """RFC1918 private addresses are forgery attempts, not leaks."""
    for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
        row = _log_row({"X-Forwarded-For": ip})
        assert _detect_ip_leak(row, row["fields"]["headers"]) is None, ip


def test_xff_link_local_is_not_a_leak():
    row = _log_row({"X-Forwarded-For": "169.254.1.1"})
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_forwarded_header_rfc7239_parsed():
    row = _log_row({"Forwarded": "for=1.2.3.4;by=5.6.7.8"})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["real_ip_claim"] == "1.2.3.4"
    assert result["source_header"] == "Forwarded"


def test_forwarded_with_ipv6_and_port():
    row = _log_row({"Forwarded": 'for="[2606:4700:4700::1111]:4711"'})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["real_ip_claim"] == "2606:4700:4700::1111"


def test_x_real_ip_fallback():
    row = _log_row({"X-Real-IP": "1.1.1.1"})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["source_header"] == "X-Real-IP"
    assert result["real_ip_claim"] == "1.1.1.1"


def test_cf_connecting_ip_variant():
    row = _log_row({"CF-Connecting-IP": "1.0.0.1"})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["source_header"] == "CF-Connecting-IP"
    assert result["real_ip_claim"] == "1.0.0.1"


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
    row = _log_row({"x-forwarded-for": "1.1.1.1"})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["real_ip_claim"] == "1.1.1.1"


def test_trusted_proxy_source_skipped(monkeypatch):
    monkeypatch.setenv("DECNET_TRUSTED_PROXIES", "8.8.8.8")
    row = _log_row({"X-Forwarded-For": "1.1.1.1"})
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_trusted_proxy_cidr(monkeypatch):
    monkeypatch.setenv("DECNET_TRUSTED_PROXIES", "8.8.8.0/24")
    row = _log_row({"X-Forwarded-For": "1.1.1.1"})
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_malformed_xff_falls_through_to_next_parseable():
    row = _log_row({"X-Forwarded-For": "garbage, 1.1.1.1, not-ip"})
    result = _detect_ip_leak(row, row["fields"]["headers"])
    assert result is not None
    assert result["real_ip_claim"] == "1.1.1.1"


def test_all_values_unparseable_bails():
    row = _log_row({"X-Forwarded-For": "not-ip, still-not-ip"})
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_no_headers_skipped():
    row = _log_row({})
    assert _detect_ip_leak(row, {}) is None


def test_non_http_service_skipped():
    row = _log_row(
        {"X-Forwarded-For": "1.1.1.1"},
        service="ssh",
    )
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


def test_missing_attacker_ip_bails():
    row = _log_row({"X-Forwarded-For": "1.1.1.1"}, source_ip="")
    assert _detect_ip_leak(row, row["fields"]["headers"]) is None


# ─── end-to-end via _extract_bounty ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_extract_bounty_emits_ip_leak_row():
    row = _log_row({
        "X-Forwarded-For": "1.1.1.1",
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
    assert payload["real_ip_claim"] == "1.1.1.1"
    assert payload["source_ip"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_extract_bounty_no_leak_no_call():
    row = _log_row({"X-Forwarded-For": "8.8.8.8"})  # matches source
    repo = AsyncMock()
    await _extract_bounty(repo, row)

    types = [
        call.args[0]["bounty_type"]
        for call in repo.add_bounty.call_args_list
    ]
    assert "ip_leak" not in types


# ─── spoofed-source (non-routable claim) classification ─────────────────────

def test_categorize_public():
    assert _categorize_claimed_ip("8.8.8.8") == "public"
    assert _categorize_claimed_ip("2606:4700:4700::1111") == "public"


def test_categorize_loopback():
    assert _categorize_claimed_ip("127.0.0.1") == "loopback"
    assert _categorize_claimed_ip("::1") == "loopback"


def test_categorize_private():
    for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
        assert _categorize_claimed_ip(ip) == "private", ip


def test_categorize_link_local():
    assert _categorize_claimed_ip("169.254.1.1") == "link_local"
    assert _categorize_claimed_ip("fe80::1") == "link_local"


def test_categorize_multicast_and_reserved():
    assert _categorize_claimed_ip("224.0.0.1") == "multicast"
    # 240.0.0.1 is reserved (class E).
    assert _categorize_claimed_ip("240.0.0.1") == "reserved"


def test_categorize_unparseable():
    assert _categorize_claimed_ip("not-an-ip") == "unparseable"
    assert _categorize_claimed_ip("") == "unparseable"


def test_spoofed_source_fires_on_loopback_waf_bypass():
    """The original motivating case: curl -H 'X-Forwarded-For: 127.0.0.1'
    must produce a spoofed_source fingerprint, NOT an ip_leak."""
    row = _log_row({"X-Forwarded-For": "127.0.0.1"})
    result = _detect_spoofed_source(row, row["fields"]["headers"])
    assert result is not None
    assert result["fingerprint_type"] == "spoofed_source"
    assert result["claim_category"] == "loopback"
    assert result["claimed_ip"] == "127.0.0.1"
    assert result["source_ip"] == "8.8.8.8"


def test_spoofed_source_fires_on_rfc1918():
    row = _log_row({"X-Forwarded-For": "10.0.0.5"})
    result = _detect_spoofed_source(row, row["fields"]["headers"])
    assert result is not None
    assert result["claim_category"] == "private"


def test_spoofed_source_skipped_on_public_claim():
    """A public-IP claim is a leak, not a spoof — the two detectors
    are mutually exclusive."""
    row = _log_row({"X-Forwarded-For": "1.1.1.1"})
    assert _detect_spoofed_source(row, row["fields"]["headers"]) is None


def test_spoofed_source_skipped_when_matches_source():
    row = _log_row({"X-Forwarded-For": "8.8.8.8"})
    assert _detect_spoofed_source(row, row["fields"]["headers"]) is None


def test_spoofed_source_respects_trusted_proxy(monkeypatch):
    monkeypatch.setenv("DECNET_TRUSTED_PROXIES", "8.8.8.8")
    row = _log_row({"X-Forwarded-For": "127.0.0.1"})
    assert _detect_spoofed_source(row, row["fields"]["headers"]) is None


@pytest.mark.asyncio
async def test_extract_bounty_emits_spoofed_source_fingerprint():
    row = _log_row({"X-Forwarded-For": "127.0.0.1"})
    repo = AsyncMock()
    await _extract_bounty(repo, row)

    calls = [c.args[0] for c in repo.add_bounty.call_args_list]
    # ip_leak must NOT fire for the loopback case.
    assert all(c["bounty_type"] != "ip_leak" for c in calls)
    # A fingerprint with fingerprint_type=spoofed_source should fire.
    spoof = next(
        (c for c in calls
         if c["bounty_type"] == "fingerprint"
         and c["payload"].get("fingerprint_type") == "spoofed_source"),
        None,
    )
    assert spoof is not None
    assert spoof["payload"]["claim_category"] == "loopback"
