"""
Tests for JARM bounty extraction in the ingester.

Verifies that _extract_bounty() correctly identifies and stores JARM
fingerprints from prober events, and ignores JARM fields from other services.
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
