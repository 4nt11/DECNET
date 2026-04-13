"""Tests for attacker fingerprint extraction in the ingester."""

import pytest
from unittest.mock import AsyncMock, MagicMock, call
from decnet.web.ingester import _extract_bounty


def _make_repo():
    repo = MagicMock()
    repo.add_bounty = AsyncMock()
    return repo


# ---------------------------------------------------------------------------
# HTTP User-Agent
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_http_useragent_extracted():
    repo = _make_repo()
    log_data = {
        "decky": "decky-01",
        "service": "http",
        "attacker_ip": "10.0.0.1",
        "event_type": "request",
        "fields": {
            "method": "GET",
            "path": "/admin",
            "headers": {"User-Agent": "Nikto/2.1.6", "Host": "target"},
        },
    }
    await _extract_bounty(repo, log_data)
    repo.add_bounty.assert_awaited_once()
    call_kwargs = repo.add_bounty.call_args[0][0]
    assert call_kwargs["bounty_type"] == "fingerprint"
    assert call_kwargs["payload"]["fingerprint_type"] == "http_useragent"
    assert call_kwargs["payload"]["value"] == "Nikto/2.1.6"
    assert call_kwargs["payload"]["path"] == "/admin"
    assert call_kwargs["payload"]["method"] == "GET"


@pytest.mark.asyncio
async def test_http_useragent_lowercase_key():
    repo = _make_repo()
    log_data = {
        "decky": "decky-01",
        "service": "http",
        "attacker_ip": "10.0.0.2",
        "event_type": "request",
        "fields": {
            "headers": {"user-agent": "sqlmap/1.7"},
        },
    }
    await _extract_bounty(repo, log_data)
    call_kwargs = repo.add_bounty.call_args[0][0]
    assert call_kwargs["payload"]["value"] == "sqlmap/1.7"


@pytest.mark.asyncio
async def test_http_no_useragent_no_fingerprint_bounty():
    repo = _make_repo()
    log_data = {
        "decky": "decky-01",
        "service": "http",
        "attacker_ip": "10.0.0.3",
        "event_type": "request",
        "fields": {
            "headers": {"Host": "target"},
        },
    }
    await _extract_bounty(repo, log_data)
    repo.add_bounty.assert_not_awaited()


@pytest.mark.asyncio
async def test_http_headers_not_dict_no_crash():
    repo = _make_repo()
    log_data = {
        "decky": "decky-01",
        "service": "http",
        "attacker_ip": "10.0.0.4",
        "event_type": "request",
        "fields": {"headers": "raw-string-not-a-dict"},
    }
    await _extract_bounty(repo, log_data)
    repo.add_bounty.assert_not_awaited()


# ---------------------------------------------------------------------------
# VNC client version
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vnc_client_version_extracted():
    repo = _make_repo()
    log_data = {
        "decky": "decky-02",
        "service": "vnc",
        "attacker_ip": "10.0.0.5",
        "event_type": "version",
        "fields": {"client_version": "RFB 003.008", "src": "10.0.0.5"},
    }
    await _extract_bounty(repo, log_data)
    repo.add_bounty.assert_awaited_once()
    call_kwargs = repo.add_bounty.call_args[0][0]
    assert call_kwargs["bounty_type"] == "fingerprint"
    assert call_kwargs["payload"]["fingerprint_type"] == "vnc_client_version"
    assert call_kwargs["payload"]["value"] == "RFB 003.008"


@pytest.mark.asyncio
async def test_vnc_non_version_event_no_fingerprint():
    repo = _make_repo()
    log_data = {
        "decky": "decky-02",
        "service": "vnc",
        "attacker_ip": "10.0.0.6",
        "event_type": "auth_response",
        "fields": {"client_version": "RFB 003.008", "src": "10.0.0.6"},
    }
    await _extract_bounty(repo, log_data)
    repo.add_bounty.assert_not_awaited()


@pytest.mark.asyncio
async def test_vnc_version_event_no_client_version_field():
    repo = _make_repo()
    log_data = {
        "decky": "decky-02",
        "service": "vnc",
        "attacker_ip": "10.0.0.7",
        "event_type": "version",
        "fields": {"src": "10.0.0.7"},
    }
    await _extract_bounty(repo, log_data)
    repo.add_bounty.assert_not_awaited()


# ---------------------------------------------------------------------------
# Credential extraction unaffected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_credential_still_extracted_alongside_fingerprint():
    repo = _make_repo()
    log_data = {
        "decky": "decky-03",
        "service": "ftp",
        "attacker_ip": "10.0.0.8",
        "event_type": "auth_attempt",
        "fields": {"username": "admin", "password": "1234"},
    }
    await _extract_bounty(repo, log_data)
    repo.add_bounty.assert_awaited_once()
    call_kwargs = repo.add_bounty.call_args[0][0]
    assert call_kwargs["bounty_type"] == "credential"


@pytest.mark.asyncio
async def test_http_credential_and_fingerprint_both_extracted():
    """An HTTP login attempt can yield both a credential and a UA fingerprint."""
    repo = _make_repo()
    log_data = {
        "decky": "decky-03",
        "service": "http",
        "attacker_ip": "10.0.0.9",
        "event_type": "request",
        "fields": {
            "username": "root",
            "password": "toor",
            "headers": {"User-Agent": "curl/7.88.1"},
        },
    }
    await _extract_bounty(repo, log_data)
    assert repo.add_bounty.await_count == 2
    types = {c[0][0]["bounty_type"] for c in repo.add_bounty.call_args_list}
    assert types == {"credential", "fingerprint"}


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fields_not_dict_no_crash():
    repo = _make_repo()
    log_data = {
        "decky": "decky-04",
        "service": "http",
        "attacker_ip": "10.0.0.10",
        "event_type": "request",
        "fields": None,
    }
    await _extract_bounty(repo, log_data)
    repo.add_bounty.assert_not_awaited()


@pytest.mark.asyncio
async def test_fields_missing_entirely_no_crash():
    repo = _make_repo()
    log_data = {
        "decky": "decky-04",
        "service": "http",
        "attacker_ip": "10.0.0.11",
        "event_type": "request",
    }
    await _extract_bounty(repo, log_data)
    repo.add_bounty.assert_not_awaited()
