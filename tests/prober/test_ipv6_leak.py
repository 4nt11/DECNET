# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for Ipv6LeakProbe and the underlying ipv6_leak helpers.

Covers:
- Ipv6LeakProbe.run() skips when not on-link or iface unknown.
- Ipv6LeakProbe.run() returns evidence dict on success.
- Ipv6LeakProbe.run() returns None when solicit returns None.
- Ipv6LeakProbe.run() returns None and logs on solicit exception.
- Ipv6LeakProbe.syslog_fields() produces correct SD fields and human message.
- Ipv6LeakProbe.publish_payload() produces correct bus payload.
- _route_info calls _ip_route_get exactly once and parses (on_link, iface).
- _ip_route_get subprocess failure is logged at debug and returns "".
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

_EVIDENCE = {
    "addr": "fe80::aabb:ccff:fedd:eeff",
    "mac_oui": "a8:bb:cc",
    "iid_kind": "eui64",
    "vector": "active_echo",
    "on_iface": "eth0",
    "attacker_v4": "10.0.0.9",
    "observed_at": "2026-01-01T00:00:00+00:00",
}


# ─── Ipv6LeakProbe.run() ─────────────────────────────────────────────────────

def _make_probe():
    from decnet.prober.probes.ipv6_leak_probe import Ipv6LeakProbe
    return Ipv6LeakProbe()


def test_run_skips_when_not_on_link() -> None:
    probe = _make_probe()
    with (
        patch("decnet.prober.ipv6_leak._route_info", return_value=(False, "eth0")),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak") as mock_sol,
    ):
        result = probe.run("10.0.0.9", None, 1.0)
    assert result is None
    mock_sol.assert_not_called()


def test_run_skips_when_no_iface() -> None:
    probe = _make_probe()
    with (
        patch("decnet.prober.ipv6_leak._route_info", return_value=(True, None)),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak") as mock_sol,
    ):
        result = probe.run("10.0.0.9", None, 1.0)
    assert result is None
    mock_sol.assert_not_called()


def test_run_returns_evidence_on_success() -> None:
    probe = _make_probe()
    with (
        patch("decnet.prober.ipv6_leak._route_info", return_value=(True, "eth0")),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", return_value=_EVIDENCE),
    ):
        result = probe.run("10.0.0.9", None, 1.0)
    assert result == _EVIDENCE


def test_run_returns_none_when_solicit_returns_none() -> None:
    probe = _make_probe()
    with (
        patch("decnet.prober.ipv6_leak._route_info", return_value=(True, "eth0")),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", return_value=None),
    ):
        result = probe.run("10.0.0.9", None, 1.0)
    assert result is None


def test_run_propagates_solicit_exception() -> None:
    """Exceptions from solicit_ipv6_leak bubble up to _run_probe's except clause."""
    probe = _make_probe()
    with (
        patch("decnet.prober.ipv6_leak._route_info", return_value=(True, "eth0")),
        patch("decnet.prober.ipv6_leak.solicit_ipv6_leak", side_effect=RuntimeError("boom")),
    ):
        try:
            probe.run("10.0.0.9", None, 1.0)
            raised = False
        except RuntimeError:
            raised = True
    assert raised


# ─── Ipv6LeakProbe.syslog_fields() ──────────────────────────────────────────

def test_syslog_fields_structure() -> None:
    probe = _make_probe()
    fields, msg = probe.syslog_fields("10.0.0.9", None, _EVIDENCE)
    assert fields["ipv6_addr"] == _EVIDENCE["addr"]
    assert fields["iid_kind"] == "eui64"
    assert fields["mac_oui"] == "a8:bb:cc"
    assert fields["on_iface"] == "eth0"
    assert fields["vector"] == "active_echo"
    assert "10.0.0.9" in msg
    assert _EVIDENCE["addr"] in msg


def test_syslog_fields_byte_stable() -> None:
    """SD field keys are stable — callers rely on them for syslog parsing."""
    probe = _make_probe()
    fields, _ = probe.syslog_fields("10.0.0.9", None, _EVIDENCE)
    assert set(fields.keys()) == {"ipv6_addr", "iid_kind", "mac_oui", "on_iface", "vector"}


# ─── Ipv6LeakProbe.publish_payload() ────────────────────────────────────────

def test_publish_payload_structure() -> None:
    probe = _make_probe()
    payload = probe.publish_payload("10.0.0.9", None, _EVIDENCE)
    assert payload["attacker_ip"] == "10.0.0.9"
    assert payload["addr"] == _EVIDENCE["addr"]
    assert payload["iid_kind"] == "eui64"
    assert payload["mac_oui"] == "a8:bb:cc"
    assert payload["observed_at"] == _EVIDENCE["observed_at"]


# ─── _route_info / _ip_route_get unit tests ──────────────────────────────────

def test_route_info_calls_ip_route_get_once() -> None:
    from decnet.prober.ipv6_leak import _route_info
    stdout = "10.0.0.9 dev eth0 src 10.0.0.1 uid 0\n    cache"
    with patch("decnet.prober.ipv6_leak._ip_route_get", return_value=stdout) as mock_rg:
        on_link, iface = _route_info("10.0.0.9")
    mock_rg.assert_called_once_with("10.0.0.9")
    assert on_link is True
    assert iface == "eth0"


def test_route_info_detects_gateway() -> None:
    from decnet.prober.ipv6_leak import _route_info
    stdout = "10.0.0.9 via 192.168.1.1 dev eth0 src 192.168.1.50\n    cache"
    with patch("decnet.prober.ipv6_leak._ip_route_get", return_value=stdout):
        on_link, iface = _route_info("10.0.0.9")
    assert on_link is False
    assert iface == "eth0"


def test_ip_route_get_logs_on_subprocess_failure() -> None:
    from decnet.prober.ipv6_leak import _ip_route_get
    with (
        patch("decnet.prober.ipv6_leak.subprocess.run", side_effect=OSError("no ip")),
        patch("decnet.prober.ipv6_leak._log") as mock_log,
    ):
        result = _ip_route_get("10.0.0.9")
    assert result == ""
    mock_log.debug.assert_called_once()
    assert "10.0.0.9" in str(mock_log.debug.call_args.args)


def test_ip_route_get_returns_empty_string_on_failure() -> None:
    from decnet.prober.ipv6_leak import _ip_route_get
    with (
        patch("decnet.prober.ipv6_leak.subprocess.run", side_effect=OSError("no ip binary")),
        patch("decnet.prober.ipv6_leak._log") as mock_log,
    ):
        result = _ip_route_get("10.0.0.9")
    assert result == ""
    assert mock_log.debug.called
    assert "10.0.0.9" in str(mock_log.debug.call_args.args)
