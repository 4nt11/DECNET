# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for MalwareBazaarProvider (DEBT-046).

Bulk-feed shape: one HTTP fetch loads ``_known``, subsequent
``is_known_bad`` calls hit memory. We assert:

* no auth key → silent no-op (False, no HTTP traffic)
* fresh provider triggers exactly one refresh, then answers from cache
* hits / misses by exact 64-char hex match (case-insensitive)
* refresh failure keeps last-known-good data + does not raise
* CSV header detection survives column reordering
* ZIP'd dump is unwrapped before parsing
"""
from __future__ import annotations

import csv
import io
import zipfile

import httpx
import pytest

from decnet.intel.mal_hash import MalwareBazaarProvider, _extract_hashes


def _install_transport(handler) -> list[httpx.Request]:
    captured: list[httpx.Request] = []

    async def _wrapped(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return await handler(request)

    transport = httpx.MockTransport(_wrapped)
    from decnet.intel import mal_hash as mod

    def _factory(*, timeout: float = 60.0):
        return httpx.AsyncClient(
            transport=transport, timeout=timeout,
        )

    mod.stealth_client = _factory  # type: ignore[assignment]
    return captured


def _zip_csv(rows: list[dict[str, str]]) -> bytes:
    buf = io.StringIO()
    if not rows:
        return b""
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    raw_csv = buf.getvalue().encode()
    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("full.csv", raw_csv)
    return zip_buf.getvalue()


_HASH_A = "a" * 64
_HASH_B = "b" * 64
_HASH_C = "c" * 64


@pytest.mark.asyncio
async def test_disabled_when_auth_key_unset(monkeypatch):
    monkeypatch.delenv("DECNET_MALWAREBAZAAR_AUTH_KEY", raising=False)
    async def _h(_req):
        return httpx.Response(200, content=_zip_csv([]))
    captured = _install_transport(_h)
    p = MalwareBazaarProvider()
    assert p.disabled is True
    assert await p.is_known_bad(_HASH_A) is False
    assert captured == []  # no network call ever


@pytest.mark.asyncio
async def test_refresh_populates_known_set():
    body = _zip_csv([
        {"sha256_hash": _HASH_A, "signature": "Emotet"},
        {"sha256_hash": _HASH_B, "signature": "TrickBot"},
    ])

    async def _h(_req):
        return httpx.Response(200, content=body)
    captured = _install_transport(_h)
    p = MalwareBazaarProvider(auth_key="test-key")

    assert await p.is_known_bad(_HASH_A) is True
    assert await p.is_known_bad(_HASH_B) is True
    assert await p.is_known_bad(_HASH_C) is False
    # All four lookups answered from one refresh.
    assert len(captured) == 1
    # Auth-Key header threaded through.
    assert captured[0].headers.get("Auth-Key") == "test-key"


@pytest.mark.asyncio
async def test_lookup_is_case_insensitive():
    body = _zip_csv([{"sha256_hash": _HASH_A.upper(), "signature": "x"}])

    async def _h(_req):
        return httpx.Response(200, content=body)
    _install_transport(_h)
    p = MalwareBazaarProvider(auth_key="k")
    # Provider lowercases on parse + lowercases the query.
    assert await p.is_known_bad(_HASH_A.upper()) is True


@pytest.mark.asyncio
async def test_refresh_failure_keeps_last_known_good():
    """First refresh succeeds with one hash; the next refresh after TTL
    expiry returns 500 — provider must keep answering from the prior
    set, not lose it."""
    call_count = {"n": 0}

    async def handler(req):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return httpx.Response(
                200, content=_zip_csv([{"sha256_hash": _HASH_A, "signature": "x"}]),
            )
        return httpx.Response(500, content=b"")

    _install_transport(handler)
    p = MalwareBazaarProvider(auth_key="k", refresh_interval_s=0.0)
    assert await p.is_known_bad(_HASH_A) is True
    # Second call: TTL=0 forces refresh; refresh fails; cache survives.
    assert await p.is_known_bad(_HASH_A) is True
    assert p._last_error is not None


@pytest.mark.asyncio
async def test_refresh_network_error_does_not_raise():
    async def handler(req):
        raise httpx.ConnectError("boom")

    _install_transport(handler)
    p = MalwareBazaarProvider(auth_key="k")
    assert await p.is_known_bad(_HASH_A) is False
    assert p._last_error is not None


def test_extract_hashes_skips_comment_lines():
    text = (
        "# Generated 2026-05-03\n"
        "# Header: comment\n"
        "sha256_hash,signature\n"
        f"{_HASH_A},Emotet\n"
        f"{_HASH_B},Cobalt Strike\n"
    )
    out = _extract_hashes(text)
    assert out == {_HASH_A, _HASH_B}


def test_extract_hashes_drops_invalid_rows():
    text = (
        "sha256_hash,signature\n"
        f"{_HASH_A},Emotet\n"
        "not-a-hash,foo\n"
        "shorthex,bar\n"
        f"{'g' * 64},badchars\n"  # right length, wrong charset
    )
    out = _extract_hashes(text)
    assert out == {_HASH_A}


def test_extract_hashes_finds_column_after_reorder():
    text = (
        "first_seen,sha256_hash,signature\n"
        f"2026-05-03,{_HASH_A},Emotet\n"
    )
    out = _extract_hashes(text)
    assert out == {_HASH_A}
