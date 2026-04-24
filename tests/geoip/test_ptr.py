"""Unit tests for decnet.geoip.ptr — reverse-DNS resolver."""
from __future__ import annotations

import asyncio
import socket
from unittest.mock import patch

import pytest

from decnet.geoip.ptr import _is_resolvable, resolve_ptr_record


@pytest.fixture(autouse=True)
def _enable_ptr(monkeypatch):
    """This module covers the resolver directly — re-enable the env
    switch that tests/conftest.py disables globally."""
    monkeypatch.setenv("DECNET_PTR_ENABLED", "true")


# ─── pure predicate ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("ip", [
    "127.0.0.1",
    "10.0.0.1",
    "192.168.1.5",
    "172.16.0.1",
    "169.254.1.1",   # link-local
    "224.0.0.1",     # multicast
    "::1",
    "fe80::1",       # IPv6 link-local
    "not-an-ip",
    "",
])
def test_not_resolvable(ip: str):
    assert _is_resolvable(ip) is False


@pytest.mark.parametrize("ip", [
    "8.8.8.8",
    "1.1.1.1",
    "2606:4700:4700::1111",
])
def test_resolvable_public(ip: str):
    assert _is_resolvable(ip) is True


# ─── resolver ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_resolves_public_ip():
    with patch(
        "decnet.geoip.ptr.socket.gethostbyaddr",
        return_value=("dns.google", [], ["8.8.8.8"]),
    ):
        name = await resolve_ptr_record("8.8.8.8")
    assert name == "dns.google"


@pytest.mark.asyncio
async def test_private_ip_short_circuits():
    """Private IPs never touch the resolver."""
    with patch("decnet.geoip.ptr.socket.gethostbyaddr") as mock_lookup:
        assert await resolve_ptr_record("127.0.0.1") is None
        assert await resolve_ptr_record("10.0.0.1") is None
        assert await resolve_ptr_record("::1") is None
        assert mock_lookup.call_count == 0


@pytest.mark.asyncio
async def test_gethostbyaddr_herror_returns_none():
    with patch(
        "decnet.geoip.ptr.socket.gethostbyaddr",
        side_effect=socket.herror("no rDNS"),
    ):
        assert await resolve_ptr_record("8.8.8.8") is None


@pytest.mark.asyncio
async def test_gethostbyaddr_gaierror_returns_none():
    with patch(
        "decnet.geoip.ptr.socket.gethostbyaddr",
        side_effect=socket.gaierror("dns broken"),
    ):
        assert await resolve_ptr_record("8.8.8.8") is None


@pytest.mark.asyncio
async def test_timeout_returns_none():
    """A slow resolver should not block the caller past timeout."""
    def slow(ip: str):  # noqa: ARG001
        import time
        time.sleep(3.0)
        return ("slow.example", [], [])

    with patch("decnet.geoip.ptr.socket.gethostbyaddr", side_effect=slow):
        # Tight timeout — must return quickly.
        result = await asyncio.wait_for(
            resolve_ptr_record("8.8.8.8", timeout=0.1),
            timeout=1.0,
        )
    assert result is None


@pytest.mark.asyncio
async def test_env_disabled(monkeypatch):
    monkeypatch.setenv("DECNET_PTR_ENABLED", "false")
    with patch("decnet.geoip.ptr.socket.gethostbyaddr") as mock_lookup:
        assert await resolve_ptr_record("8.8.8.8") is None
        assert mock_lookup.call_count == 0


@pytest.mark.asyncio
async def test_empty_hostname_returned_as_none():
    """gethostbyaddr can return '' on some platforms; normalize to None."""
    with patch(
        "decnet.geoip.ptr.socket.gethostbyaddr",
        return_value=("", [], ["8.8.8.8"]),
    ):
        assert await resolve_ptr_record("8.8.8.8") is None
