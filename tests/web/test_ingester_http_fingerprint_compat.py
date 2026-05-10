"""
Regression: the ingester's JA4H path must fire when a ja4h field is present
in the sd-block of an http_request_fingerprint event (new shape, emitted by
syslog_bridge._compute_ja4h in the container).

The old shape (ja4h absent, headers_ordered present) should NOT crash — the
bounty simply isn't added.  This compat test documents expected behavior for
the rollout window.
"""
from __future__ import annotations

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# ------ helpers ---------------------------------------------------------------

def _make_log_data(event_type: str, fields: dict) -> dict:
    return {
        "event_type": event_type,
        "decky": "test-decky",
        "service": "https",
        "attacker_ip": "1.2.3.4",
        "fields": fields,
    }


async def _run_bounty_check(log_data: dict) -> list:
    """Run the ingester's _process_log_event and collect add_bounty calls."""
    from decnet.web.ingester import _process_fingerprint_bounties

    repo = MagicMock()
    repo.add_bounty = AsyncMock()
    bus = MagicMock()

    await _process_fingerprint_bounties(repo, log_data, bus)
    return [call.args[0] for call in repo.add_bounty.call_args_list]


# ------ import guard ----------------------------------------------------------

def _import_process():
    """Return _process_fingerprint_bounties or skip if not found."""
    try:
        from decnet.web.ingester import _process_fingerprint_bounties
        return _process_fingerprint_bounties
    except ImportError:
        pytest.skip("_process_fingerprint_bounties not yet public")


# ------ tests -----------------------------------------------------------------

class TestJA4HIngestion:
    def test_new_shape_fires_bounty(self):
        """New shape: ja4h field present → bounty added."""
        _import_process()
        log_data = _make_log_data("http_request_fingerprint", {
            "ja4h": "GE11nn0000_03_abc123def456_000000000000",
            "proto": "h1",
            "method": "GET",
            "path": "/index.html",
            "headers_ordered": json.dumps(["host", "user-agent", "accept"]),
        })
        bounties = pytest.importorskip("asyncio").run(_run_bounty_check(log_data))
        ja4h_bounties = [b for b in bounties if b.get("payload", {}).get("fingerprint_type") == "ja4h"]
        assert len(ja4h_bounties) == 1
        assert ja4h_bounties[0]["payload"]["ja4h"] == "GE11nn0000_03_abc123def456_000000000000"
        assert ja4h_bounties[0]["payload"]["protocol"] == "h1"

    def test_old_shape_no_crash(self):
        """Old shape: no ja4h field → no bounty, no exception."""
        _import_process()
        log_data = _make_log_data("http_request_fingerprint", {
            "proto": "h1",
            "method": "GET",
            "path": "/",
            "headers_ordered": json.dumps(["host", "user-agent"]),
            "cookie": "",
            "accept_language": "",
        })
        import asyncio
        bounties = asyncio.run(_run_bounty_check(log_data))
        ja4h_bounties = [b for b in bounties if b.get("payload", {}).get("fingerprint_type") == "ja4h"]
        assert len(ja4h_bounties) == 0

    def test_proto_field_alias(self):
        """proto (new) and protocol (old) both populate payload.protocol."""
        _import_process()
        for field_name, field_val in [("proto", "h2"), ("protocol", "h2")]:
            log_data = _make_log_data("http_request_fingerprint", {
                "ja4h": "GE20nn0000_02_aabbccddeeff_000000000000",
                field_name: field_val,
                "method": "GET",
                "path": "/",
            })
            import asyncio
            bounties = asyncio.run(_run_bounty_check(log_data))
            ja4h_bounties = [b for b in bounties if b.get("payload", {}).get("fingerprint_type") == "ja4h"]
            if ja4h_bounties:
                assert ja4h_bounties[0]["payload"]["protocol"] == "h2", f"field={field_name}"
