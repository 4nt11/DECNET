"""
Tests for prober bounty extraction in the ingester.

Verifies that _extract_bounty() correctly identifies and stores JARM,
HASSH, and TCP/IP fingerprints from prober events, and ignores these
fields when they come from other services.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from decnet.web.ingester import _extract_bounty


def _make_repo() -> MagicMock:
    repo = MagicMock()
    repo.add_bounty = AsyncMock()
    return repo


@pytest.mark.asyncio
async def test_jarm_bounty_extracted():
    """Prober event with jarm_hash should create a fingerprint bounty."""
    repo = _make_repo()
    log_data = {
        "decky": "decnet-prober",
        "service": "prober",
        "event_type": "jarm_fingerprint",
        "attacker_ip": "Unknown",
        "fields": {
            "target_ip": "10.0.0.1",
            "target_port": "443",
            "jarm_hash": "c0cc0cc0cc0cc0cc0cc0cc0cc0cc0cabcdef1234567890abcdef1234567890ab",
        },
        "msg": "JARM 10.0.0.1:443 = ...",
    }

    await _extract_bounty(repo, log_data)

    repo.add_bounty.assert_called()
    call_args = repo.add_bounty.call_args[0][0]
    assert call_args["service"] == "prober"
    assert call_args["bounty_type"] == "fingerprint"
    assert call_args["attacker_ip"] == "10.0.0.1"
    assert call_args["payload"]["fingerprint_type"] == "jarm"
    assert call_args["payload"]["hash"] == "c0cc0cc0cc0cc0cc0cc0cc0cc0cc0cabcdef1234567890abcdef1234567890ab"
    assert call_args["payload"]["target_ip"] == "10.0.0.1"
    assert call_args["payload"]["target_port"] == "443"


@pytest.mark.asyncio
async def test_jarm_bounty_not_extracted_from_other_services():
    """A non-prober event with jarm_hash field should NOT trigger extraction."""
    repo = _make_repo()
    log_data = {
        "decky": "decky-01",
        "service": "sniffer",
        "event_type": "tls_client_hello",
        "attacker_ip": "192.168.1.50",
        "fields": {
            "jarm_hash": "fake_hash_from_different_service",
        },
        "msg": "",
    }

    await _extract_bounty(repo, log_data)

    # Should NOT have been called for JARM — sniffer has its own bounty types
    for call in repo.add_bounty.call_args_list:
        payload = call[0][0].get("payload", {})
        assert payload.get("fingerprint_type") != "jarm"


@pytest.mark.asyncio
async def test_jarm_bounty_not_extracted_without_hash():
    """Prober event without jarm_hash should not create a bounty."""
    repo = _make_repo()
    log_data = {
        "decky": "decnet-prober",
        "service": "prober",
        "event_type": "prober_startup",
        "attacker_ip": "Unknown",
        "fields": {
            "target_count": "5",
            "interval": "300",
        },
        "msg": "DECNET-PROBER started",
    }

    await _extract_bounty(repo, log_data)

    for call in repo.add_bounty.call_args_list:
        payload = call[0][0].get("payload", {})
        assert payload.get("fingerprint_type") != "jarm"


@pytest.mark.asyncio
async def test_jarm_bounty_missing_fields_dict():
    """Log data without 'fields' dict should not crash."""
    repo = _make_repo()
    log_data = {
        "decky": "decnet-prober",
        "service": "prober",
        "event_type": "jarm_fingerprint",
        "attacker_ip": "Unknown",
    }

    await _extract_bounty(repo, log_data)
    # No bounty calls for JARM
    for call in repo.add_bounty.call_args_list:
        payload = call[0][0].get("payload", {})
        assert payload.get("fingerprint_type") != "jarm"


# ─── HASSH bounty extraction ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_hassh_bounty_extracted():
    """Prober event with hassh_server_hash should create a fingerprint bounty."""
    repo = _make_repo()
    log_data = {
        "decky": "decnet-prober",
        "service": "prober",
        "event_type": "hassh_fingerprint",
        "attacker_ip": "Unknown",
        "fields": {
            "target_ip": "10.0.0.1",
            "target_port": "22",
            "hassh_server_hash": "a" * 32,
            "ssh_banner": "SSH-2.0-OpenSSH_8.9p1",
            "kex_algorithms": "curve25519-sha256",
            "encryption_s2c": "aes256-gcm@openssh.com",
            "mac_s2c": "hmac-sha2-256-etm@openssh.com",
            "compression_s2c": "none",
        },
        "msg": "HASSH 10.0.0.1:22 = ...",
    }

    await _extract_bounty(repo, log_data)

    # Find the HASSH bounty call
    hassh_calls = [
        c for c in repo.add_bounty.call_args_list
        if c[0][0].get("payload", {}).get("fingerprint_type") == "hassh_server"
    ]
    assert len(hassh_calls) == 1
    payload = hassh_calls[0][0][0]["payload"]
    assert payload["hash"] == "a" * 32
    assert payload["ssh_banner"] == "SSH-2.0-OpenSSH_8.9p1"
    assert payload["kex_algorithms"] == "curve25519-sha256"
    assert payload["encryption_s2c"] == "aes256-gcm@openssh.com"
    assert payload["mac_s2c"] == "hmac-sha2-256-etm@openssh.com"
    assert payload["compression_s2c"] == "none"


@pytest.mark.asyncio
async def test_hassh_bounty_not_extracted_from_other_services():
    """A non-prober event with hassh_server_hash should NOT trigger extraction."""
    repo = _make_repo()
    log_data = {
        "decky": "decky-01",
        "service": "ssh",
        "event_type": "login_attempt",
        "attacker_ip": "192.168.1.50",
        "fields": {
            "hassh_server_hash": "fake_hash",
        },
        "msg": "",
    }

    await _extract_bounty(repo, log_data)

    for call in repo.add_bounty.call_args_list:
        payload = call[0][0].get("payload", {})
        assert payload.get("fingerprint_type") != "hassh_server"


# ─── TCP/IP fingerprint bounty extraction ──────────────────────────────────

@pytest.mark.asyncio
async def test_tcpfp_bounty_extracted():
    """Prober event with tcpfp_hash should create a fingerprint bounty."""
    repo = _make_repo()
    log_data = {
        "decky": "decnet-prober",
        "service": "prober",
        "event_type": "tcpfp_fingerprint",
        "attacker_ip": "Unknown",
        "fields": {
            "target_ip": "10.0.0.1",
            "target_port": "443",
            "tcpfp_hash": "d" * 32,
            "tcpfp_raw": "64:65535:1:1460:7:1:1:M,N,W,N,N,T,S,E",
            "ttl": "64",
            "window_size": "65535",
            "df_bit": "1",
            "mss": "1460",
            "window_scale": "7",
            "sack_ok": "1",
            "timestamp": "1",
            "options_order": "M,N,W,N,N,T,S,E",
        },
        "msg": "TCPFP 10.0.0.1:443 = ...",
    }

    await _extract_bounty(repo, log_data)

    tcpfp_calls = [
        c for c in repo.add_bounty.call_args_list
        if c[0][0].get("payload", {}).get("fingerprint_type") == "tcpfp"
    ]
    assert len(tcpfp_calls) == 1
    payload = tcpfp_calls[0][0][0]["payload"]
    assert payload["hash"] == "d" * 32
    assert payload["raw"] == "64:65535:1:1460:7:1:1:M,N,W,N,N,T,S,E"
    assert payload["ttl"] == "64"
    assert payload["window_size"] == "65535"
    assert payload["options_order"] == "M,N,W,N,N,T,S,E"


@pytest.mark.asyncio
async def test_tcpfp_bounty_not_extracted_from_other_services():
    """A non-prober event with tcpfp_hash should NOT trigger extraction."""
    repo = _make_repo()
    log_data = {
        "decky": "decky-01",
        "service": "sniffer",
        "event_type": "something",
        "attacker_ip": "192.168.1.50",
        "fields": {
            "tcpfp_hash": "fake_hash",
        },
        "msg": "",
    }

    await _extract_bounty(repo, log_data)

    for call in repo.add_bounty.call_args_list:
        payload = call[0][0].get("payload", {})
        assert payload.get("fingerprint_type") != "tcpfp"
