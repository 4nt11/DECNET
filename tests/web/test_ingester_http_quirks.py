"""HTTP header-quirks fingerprint extraction in the ingester."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from decnet.web.ingester import (
    _casing_category,
    _guess_tool_from_order,
    _http_quirks_fingerprint,
    _short_hash,
    _extract_bounty,
)


def _log_row(headers: dict[str, str], *, service: str = "http") -> dict:
    return {
        "decky": "http-01",
        "service": service,
        "attacker_ip": "1.2.3.4",
        "event_type": "request",
        "fields": {
            "method": "GET",
            "path": "/",
            "headers": headers,
        },
    }


# ─── casing classifier ─────────────────────────────────────────────────────

def test_casing_title():
    assert _casing_category("User-Agent") == "title"
    assert _casing_category("Host") == "title"
    assert _casing_category("X-Forwarded-For") == "title"


def test_casing_lower():
    assert _casing_category("user-agent") == "lower"
    assert _casing_category("x-forwarded-for") == "lower"


def test_casing_upper():
    assert _casing_category("USER-AGENT") == "upper"


def test_casing_mixed():
    assert _casing_category("USer-AgEnt") == "mixed"


# ─── order + casing hash stability ──────────────────────────────────────────

def test_same_order_same_hash():
    row_a = _log_row({"Host": "x", "User-Agent": "curl/8", "Accept": "*/*"})
    row_b = _log_row({"Host": "y", "User-Agent": "curl/7", "Accept": "*/*"})
    fa = _http_quirks_fingerprint(row_a, row_a["fields"]["headers"])
    fb = _http_quirks_fingerprint(row_b, row_b["fields"]["headers"])
    assert fa["order_hash"] == fb["order_hash"]
    assert fa["casing_hash"] == fb["casing_hash"]


def test_different_order_different_hash():
    row_a = _log_row({"Host": "x", "User-Agent": "a", "Accept": "*/*"})
    row_b = _log_row({"Accept": "*/*", "User-Agent": "a", "Host": "x"})
    fa = _http_quirks_fingerprint(row_a, row_a["fields"]["headers"])
    fb = _http_quirks_fingerprint(row_b, row_b["fields"]["headers"])
    assert fa["order_hash"] != fb["order_hash"]


def test_different_casing_different_hash():
    row_a = _log_row({"Host": "x", "User-Agent": "a"})
    row_b = _log_row({"host": "x", "user-agent": "a"})
    fa = _http_quirks_fingerprint(row_a, row_a["fields"]["headers"])
    fb = _http_quirks_fingerprint(row_b, row_b["fields"]["headers"])
    assert fa["casing_hash"] != fb["casing_hash"]
    assert fa["casing_category"] == "title"
    assert fb["casing_category"] == "lower"


def test_volatile_headers_excluded_from_hash():
    """Content-Length, Cookie, XFF etc. are per-request; the identity
    hash shouldn't depend on them."""
    row_a = _log_row({
        "Host": "x", "User-Agent": "a", "Content-Length": "100",
    })
    row_b = _log_row({
        "Host": "x", "User-Agent": "a", "Content-Length": "999",
        "Cookie": "session=abc",
    })
    fa = _http_quirks_fingerprint(row_a, row_a["fields"]["headers"])
    fb = _http_quirks_fingerprint(row_b, row_b["fields"]["headers"])
    assert fa["order_hash"] == fb["order_hash"]
    # Count reflects ALL headers (the volatile ones WERE there).
    assert fa["header_count"] == 3
    assert fb["header_count"] == 4
    # Stable count excludes the volatile ones.
    assert fa["stable_count"] == 2
    assert fb["stable_count"] == 2


# ─── tool guesses ──────────────────────────────────────────────────────────

def test_curl_signature_guessed():
    assert _guess_tool_from_order(["host", "user-agent", "accept"]) == "curl"


def test_python_requests_signature_guessed():
    assert _guess_tool_from_order([
        "host", "user-agent", "accept-encoding", "accept", "connection",
    ]) == "python-requests"


def test_go_http_client_signature_guessed():
    assert _guess_tool_from_order([
        "host", "user-agent", "accept-encoding",
    ]) == "go-http-client"


def test_nmap_nse_signature_guessed():
    # Short order starting with host, user-agent → nmap-nse.
    assert _guess_tool_from_order(["host", "user-agent"]) == "nmap-nse"


def test_unknown_tool_returns_none():
    assert _guess_tool_from_order(["accept", "host", "user-agent"]) is None


def test_fingerprint_includes_tool_guess_curl():
    row = _log_row({
        "Host": "target", "User-Agent": "curl/8.0", "Accept": "*/*",
    })
    f = _http_quirks_fingerprint(row, row["fields"]["headers"])
    assert f["tool_guess"] == "curl"


# ─── gating ─────────────────────────────────────────────────────────────────

def test_non_http_service_skipped():
    row = _log_row({"Host": "x"}, service="ssh")
    assert _http_quirks_fingerprint(row, row["fields"]["headers"]) is None


def test_empty_headers_skipped():
    row = _log_row({})
    assert _http_quirks_fingerprint(row, {}) is None


def test_only_volatile_headers_still_emits():
    """If every header is in the volatile set we still want a fingerprint,
    just with empty order — header count alone is still a signal."""
    row = _log_row({"Content-Length": "10", "Cookie": "a=b"})
    f = _http_quirks_fingerprint(row, row["fields"]["headers"])
    assert f is not None
    assert f["header_count"] == 2
    assert f["stable_count"] == 0
    assert f["order"] == []


# ─── end-to-end via _extract_bounty ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_extract_bounty_emits_http_quirks():
    row = _log_row({
        "Host": "target", "User-Agent": "curl/8.0", "Accept": "*/*",
    })
    repo = AsyncMock()
    await _extract_bounty(repo, row)

    calls = [
        c.args[0] for c in repo.add_bounty.call_args_list
    ]
    # Expect: http_useragent fingerprint + http_quirks fingerprint.
    fp_types = [
        c["payload"].get("fingerprint_type")
        for c in calls
        if c["bounty_type"] == "fingerprint"
    ]
    assert "http_useragent" in fp_types
    assert "http_quirks" in fp_types

    quirks = next(
        c for c in calls
        if c["bounty_type"] == "fingerprint"
        and c["payload"].get("fingerprint_type") == "http_quirks"
    )
    assert quirks["payload"]["tool_guess"] == "curl"
    assert quirks["payload"]["casing_category"] == "title"


@pytest.mark.asyncio
async def test_extract_bounty_non_http_skips_quirks():
    row = _log_row({"Host": "x"}, service="ssh")
    repo = AsyncMock()
    await _extract_bounty(repo, row)
    for call in repo.add_bounty.call_args_list:
        payload = call.args[0].get("payload") or {}
        assert payload.get("fingerprint_type") != "http_quirks"


# ─── hash stability across restarts ─────────────────────────────────────────

def test_short_hash_deterministic():
    assert _short_hash("abc") == _short_hash("abc")
    assert _short_hash("abc") != _short_hash("def")
    assert len(_short_hash("anything")) == 16
