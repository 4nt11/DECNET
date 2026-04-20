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


# ---------------------------------------------------------------------------
# JA4/JA4S extraction (sniffer)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ja4_included_in_ja3_bounty():
    repo = _make_repo()
    log_data = {
        "decky": "decky-05",
        "service": "sniffer",
        "attacker_ip": "10.0.0.20",
        "event_type": "tls_session",
        "fields": {
            "ja3": "abc123",
            "ja3s": "def456",
            "ja4": "t13d0203h2_aabbccddee00_112233445566",
            "ja4s": "t1302h2_ffeeddccbbaa",
            "tls_version": "TLS 1.3",
            "dst_port": "443",
        },
    }
    await _extract_bounty(repo, log_data)
    calls = repo.add_bounty.call_args_list
    ja3_calls = [c for c in calls if c[0][0]["payload"].get("fingerprint_type") == "ja3"]
    assert len(ja3_calls) == 1
    payload = ja3_calls[0][0][0]["payload"]
    assert payload["ja4"] == "t13d0203h2_aabbccddee00_112233445566"
    assert payload["ja4s"] == "t1302h2_ffeeddccbbaa"


# ---------------------------------------------------------------------------
# JA4L latency extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ja4l_bounty_extracted():
    repo = _make_repo()
    log_data = {
        "decky": "decky-05",
        "service": "sniffer",
        "attacker_ip": "10.0.0.21",
        "event_type": "tls_session",
        "fields": {
            "ja4l_rtt_ms": "12.5",
            "ja4l_client_ttl": "64",
        },
    }
    await _extract_bounty(repo, log_data)
    calls = repo.add_bounty.call_args_list
    ja4l_calls = [c for c in calls if c[0][0]["payload"].get("fingerprint_type") == "ja4l"]
    assert len(ja4l_calls) == 1
    payload = ja4l_calls[0][0][0]["payload"]
    assert payload["rtt_ms"] == "12.5"
    assert payload["client_ttl"] == "64"


@pytest.mark.asyncio
async def test_ja4l_not_extracted_without_rtt():
    repo = _make_repo()
    log_data = {
        "decky": "decky-05",
        "service": "sniffer",
        "attacker_ip": "10.0.0.22",
        "event_type": "tls_session",
        "fields": {
            "ja4l_client_ttl": "64",
        },
    }
    await _extract_bounty(repo, log_data)
    calls = repo.add_bounty.call_args_list
    ja4l_calls = [c for c in calls if c[0][0].get("payload", {}).get("fingerprint_type") == "ja4l"]
    assert len(ja4l_calls) == 0


# ---------------------------------------------------------------------------
# TLS session resumption extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tls_resumption_bounty_extracted():
    repo = _make_repo()
    log_data = {
        "decky": "decky-05",
        "service": "sniffer",
        "attacker_ip": "10.0.0.23",
        "event_type": "tls_client_hello",
        "fields": {
            "resumption": "session_ticket,psk",
        },
    }
    await _extract_bounty(repo, log_data)
    calls = repo.add_bounty.call_args_list
    res_calls = [c for c in calls if c[0][0]["payload"].get("fingerprint_type") == "tls_resumption"]
    assert len(res_calls) == 1
    assert res_calls[0][0][0]["payload"]["mechanisms"] == "session_ticket,psk"


@pytest.mark.asyncio
async def test_no_resumption_no_bounty():
    repo = _make_repo()
    log_data = {
        "decky": "decky-05",
        "service": "sniffer",
        "attacker_ip": "10.0.0.24",
        "event_type": "tls_client_hello",
        "fields": {
            "ja3": "abc123",
        },
    }
    await _extract_bounty(repo, log_data)
    calls = repo.add_bounty.call_args_list
    res_calls = [c for c in calls if c[0][0]["payload"].get("fingerprint_type") == "tls_resumption"]
    assert len(res_calls) == 0


# ---------------------------------------------------------------------------
# TLS certificate extraction
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tls_certificate_bounty_extracted():
    repo = _make_repo()
    log_data = {
        "decky": "decky-05",
        "service": "sniffer",
        "attacker_ip": "10.0.0.25",
        "event_type": "tls_certificate",
        "fields": {
            "subject_cn": "evil.c2.local",
            "issuer": "CN=Evil CA",
            "self_signed": "true",
            "not_before": "230101000000Z",
            "not_after": "260101000000Z",
            "sans": "evil.c2.local,*.evil.c2.local",
            "sni": "evil.c2.local",
        },
    }
    await _extract_bounty(repo, log_data)
    calls = repo.add_bounty.call_args_list
    cert_calls = [c for c in calls if c[0][0]["payload"].get("fingerprint_type") == "tls_certificate"]
    assert len(cert_calls) == 1
    payload = cert_calls[0][0][0]["payload"]
    assert payload["subject_cn"] == "evil.c2.local"
    assert payload["self_signed"] == "true"
    assert payload["issuer"] == "CN=Evil CA"


@pytest.mark.asyncio
async def test_tls_certificate_not_extracted_from_non_sniffer():
    repo = _make_repo()
    log_data = {
        "decky": "decky-05",
        "service": "http",
        "attacker_ip": "10.0.0.26",
        "event_type": "tls_certificate",
        "fields": {
            "subject_cn": "not-from-sniffer.local",
        },
    }
    await _extract_bounty(repo, log_data)
    calls = repo.add_bounty.call_args_list
    cert_calls = [c for c in calls if c[0][0].get("payload", {}).get("fingerprint_type") == "tls_certificate"]
    assert len(cert_calls) == 0


# ---------------------------------------------------------------------------
# Multiple fingerprints from single sniffer log
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sniffer_log_yields_multiple_fingerprint_types():
    """A complete TLS session log with JA3 + JA4L + resumption yields 3 bounties."""
    repo = _make_repo()
    log_data = {
        "decky": "decky-05",
        "service": "sniffer",
        "attacker_ip": "10.0.0.30",
        "event_type": "tls_session",
        "fields": {
            "ja3": "abc123",
            "ja3s": "def456",
            "ja4": "t13d0203h2_aabb_ccdd",
            "ja4s": "t1302h2_eeff",
            "ja4l_rtt_ms": "5.2",
            "ja4l_client_ttl": "128",
            "resumption": "session_ticket",
            "tls_version": "TLS 1.3",
            "dst_port": "443",
        },
    }
    await _extract_bounty(repo, log_data)
    assert repo.add_bounty.await_count == 3
    types = {c[0][0]["payload"]["fingerprint_type"] for c in repo.add_bounty.call_args_list}
    assert types == {"ja3", "ja4l", "tls_resumption"}
