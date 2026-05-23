# SPDX-License-Identifier: AGPL-3.0-or-later
"""Caddyfile protocol token generation for http and https entrypoints."""
import json


def _http_protocols(versions_json: str | None) -> str:
    """Mirrors the Python inline logic in templates/http/entrypoint.sh."""
    versions = json.loads(versions_json or '["http/1.1"]')
    tokens = []
    if "http/1.1" in versions:
        tokens.append("h1")
    if "http/2" in versions:
        tokens.append("h2c")
    return " ".join(tokens) if tokens else "h1"


def _https_protocols(versions_json: str | None) -> str:
    """Mirrors the Python inline logic in templates/https/entrypoint.sh."""
    versions = json.loads(versions_json or '["http/1.1"]')
    tokens = []
    if "http/1.1" in versions:
        tokens.append("h1")
    if "http/2" in versions:
        tokens.append("h2")
    if "http/3" in versions:
        tokens.append("h3")
    return " ".join(tokens) if tokens else "h1"


# ---------------------------------------------------------------------------
# HTTP (cleartext) protocol token tests
# ---------------------------------------------------------------------------

def test_http_h1_only():
    assert _http_protocols('["http/1.1"]') == "h1"


def test_http_h1_and_h2c():
    assert _http_protocols('["http/1.1", "http/2"]') == "h1 h2c"


def test_http_h2c_only():
    assert _http_protocols('["http/2"]') == "h2c"


def test_http_default_fallback():
    assert _http_protocols(None) == "h1"


def test_http_empty_versions_fallback():
    # Should not happen (coercion rejects empty list) but guard the fallback.
    assert _http_protocols("[]") == "h1"


# ---------------------------------------------------------------------------
# HTTPS (TLS) protocol token tests
# ---------------------------------------------------------------------------

def test_https_h1_only():
    assert _https_protocols('["http/1.1"]') == "h1"


def test_https_h1_and_h2():
    assert _https_protocols('["http/1.1", "http/2"]') == "h1 h2"


def test_https_all_three():
    assert _https_protocols('["http/1.1", "http/2", "http/3"]') == "h1 h2 h3"


def test_https_h3_only():
    assert _https_protocols('["http/3"]') == "h3"


def test_https_default_fallback():
    assert _https_protocols(None) == "h1"
