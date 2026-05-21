"""Tests for Icmp6ErrorProbe and the underlying icmp6_error helpers.

Covers:
- Icmp6ErrorProbe.run() returns helper result verbatim for IPv6 targets.
- Icmp6ErrorProbe.run() returns None for IPv4 targets (address-family gate).
- Icmp6ErrorProbe.run() returns None when helper returns None.
- Icmp6ErrorProbe.syslog_fields() — stable key set, correct flag encoding, human msg.
- Icmp6ErrorProbe.publish_payload() — correct bus payload shape.
- _probe_port_unreachable_v6 / _probe_hop_limit_exceeded / _probe_unknown_next_header /
  _probe_bad_dest_option — silent-timeout cases.
- _probe_hop_limit_exceeded skipped when on-link.
- elicit_icmp6_errors returns None when scapy.layers.inet6 is unavailable.
- elicit_icmp6_errors returns None when all primitives have sent=False.
- Fingerprint hash is deterministic for identical inputs.
- Matrix encoding table-driven across all four present/absent combinations.
- Icmp6ErrorProbe registered in ActiveProbeMeta._registry.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

# ─── fixtures ────────────────────────────────────────────────────────────────

_SILENT: dict[str, Any] = {
    "returned": False,
    "rtt_ms": None,
    "src_ip": None,
    "icmp_code": None,
    "echo_len": None,
    "echo_bytes_hex": None,
}

_EVIDENCE: dict[str, Any] = {
    "matrix": "UH..",
    "fingerprint_hash": "abcdef1234567890abcdef1234567890",
    "errors": {
        "port_unreachable_v6": {
            "sent": True, "returned": True, "rtt_ms": 1.2, "src_ip": "2001:db8::1",
            "icmp_code": 4, "echo_len": 48, "echo_bytes_hex": "aabbcc",
        },
        "hop_limit_exceeded": {
            "sent": True, "returned": True, "rtt_ms": 0.7, "src_ip": "fe80::1",
            "icmp_code": 0, "echo_len": 48, "echo_bytes_hex": "ddeeff",
        },
        "unknown_next_header": dict(_SILENT),
        "bad_dest_option":     dict(_SILENT),
    },
    "observed_at": "2026-01-01T00:00:00+00:00",
}

_TARGET_V6 = "2001:db8::9"
_TARGET_V4 = "10.0.0.9"


def _make_probe():
    from decnet.prober.probes.icmp6_error_probe import Icmp6ErrorProbe
    return Icmp6ErrorProbe()


# ─── Icmp6ErrorProbe.run() ────────────────────────────────────────────────────

def test_run_returns_evidence_for_v6_target() -> None:
    probe = _make_probe()
    with patch("decnet.prober.icmp6_error.elicit_icmp6_errors", return_value=_EVIDENCE) as mock_fn:
        result = probe.run(_TARGET_V6, None, 2.0)
    assert result == _EVIDENCE
    mock_fn.assert_called_once_with(_TARGET_V6, timeout=2.0)


def test_run_returns_none_for_v4_target() -> None:
    probe = _make_probe()
    with patch("decnet.prober.icmp6_error.elicit_icmp6_errors") as mock_fn:
        result = probe.run(_TARGET_V4, None, 2.0)
    assert result is None
    mock_fn.assert_not_called()


def test_run_returns_none_when_helper_returns_none() -> None:
    probe = _make_probe()
    with patch("decnet.prober.icmp6_error.elicit_icmp6_errors", return_value=None):
        result = probe.run(_TARGET_V6, None, 2.0)
    assert result is None


# ─── Icmp6ErrorProbe.syslog_fields() ─────────────────────────────────────────

_EXPECTED_SD_KEYS = {
    "icmp6_matrix",
    "icmp6_fp_hash",
    "icmp6_port_unreach",
    "icmp6_hop_limit_exceeded",
    "icmp6_unknown_next_header",
    "icmp6_bad_dest_option",
    "icmp6_port_unreach_rtt_ms",
    "icmp6_hop_limit_exceeded_rtt_ms",
    "icmp6_unknown_next_header_rtt_ms",
    "icmp6_bad_dest_option_rtt_ms",
    "icmp6_hop_limit_exceeded_hop",
}


def test_syslog_fields_key_stable() -> None:
    probe = _make_probe()
    fields, _ = probe.syslog_fields(_TARGET_V6, None, _EVIDENCE)
    assert set(fields.keys()) == _EXPECTED_SD_KEYS


def test_syslog_fields_flag_encoding() -> None:
    probe = _make_probe()
    fields, _ = probe.syslog_fields(_TARGET_V6, None, _EVIDENCE)
    assert fields["icmp6_port_unreach"] == "1"
    assert fields["icmp6_hop_limit_exceeded"] == "1"
    assert fields["icmp6_unknown_next_header"] == "0"
    assert fields["icmp6_bad_dest_option"] == "0"


def test_syslog_fields_rtt_populated() -> None:
    probe = _make_probe()
    fields, _ = probe.syslog_fields(_TARGET_V6, None, _EVIDENCE)
    assert fields["icmp6_port_unreach_rtt_ms"] == "1.2"
    assert fields["icmp6_hop_limit_exceeded_rtt_ms"] == "0.7"
    assert fields["icmp6_unknown_next_header_rtt_ms"] == ""
    assert fields["icmp6_bad_dest_option_rtt_ms"] == ""


def test_syslog_fields_hop_limit_hop() -> None:
    probe = _make_probe()
    fields, _ = probe.syslog_fields(_TARGET_V6, None, _EVIDENCE)
    assert fields["icmp6_hop_limit_exceeded_hop"] == "fe80::1"


def test_syslog_fields_human_msg_contains_ip_and_matrix() -> None:
    probe = _make_probe()
    _, msg = probe.syslog_fields(_TARGET_V6, None, _EVIDENCE)
    assert _TARGET_V6 in msg
    assert "UH.." in msg


def test_syslog_fields_matrix_and_hash_present() -> None:
    probe = _make_probe()
    fields, _ = probe.syslog_fields(_TARGET_V6, None, _EVIDENCE)
    assert fields["icmp6_matrix"] == "UH.."
    assert fields["icmp6_fp_hash"] == _EVIDENCE["fingerprint_hash"]


# ─── Icmp6ErrorProbe.publish_payload() ───────────────────────────────────────

def test_publish_payload_structure() -> None:
    probe = _make_probe()
    payload = probe.publish_payload(_TARGET_V6, None, _EVIDENCE)
    assert payload["attacker_ip"] == _TARGET_V6
    assert payload["icmp6_matrix"] == "UH.."
    assert payload["icmp6_fp_hash"] == _EVIDENCE["fingerprint_hash"]
    assert payload["errors"] is _EVIDENCE["errors"]
    assert payload["observed_at"] == _EVIDENCE["observed_at"]


# ─── primitive: silent-on-None-response cases ─────────────────────────────────

def test_probe_port_unreachable_v6_silent_on_none_response() -> None:
    from decnet.prober.icmp6_error import _probe_port_unreachable_v6
    with patch("decnet.prober.icmp6_error._closed_udp_port", return_value=33434), \
         patch("decnet.prober.icmp6_error._ephemeral", return_value=50000):
        with patch("scapy.sendrecv.sr1", return_value=None):
            result = _probe_port_unreachable_v6(_TARGET_V6, 0.1)
    assert result["returned"] is False
    assert result["rtt_ms"] is None


def test_probe_unknown_next_header_silent_on_none_response() -> None:
    from decnet.prober.icmp6_error import _probe_unknown_next_header
    with patch("scapy.sendrecv.sr1", return_value=None):
        result = _probe_unknown_next_header(_TARGET_V6, 0.1)
    assert result["returned"] is False


def test_probe_bad_dest_option_silent_on_none_response() -> None:
    from decnet.prober.icmp6_error import _probe_bad_dest_option
    with patch("decnet.prober.icmp6_error._closed_udp_port", return_value=33434), \
         patch("decnet.prober.icmp6_error._ephemeral", return_value=50000):
        with patch("scapy.sendrecv.sr1", return_value=None):
            result = _probe_bad_dest_option(_TARGET_V6, 0.1)
    assert result["returned"] is False


def test_probe_hop_limit_exceeded_skipped_when_on_link() -> None:
    from decnet.prober.icmp6_error import _probe_hop_limit_exceeded
    with patch("scapy.sendrecv.sr1") as mock_sr1:
        result = _probe_hop_limit_exceeded(_TARGET_V6, 0.1, on_link=True)
    assert result["returned"] is False
    mock_sr1.assert_not_called()


def test_probe_hop_limit_exceeded_silent_when_not_on_link() -> None:
    from decnet.prober.icmp6_error import _probe_hop_limit_exceeded
    with patch("decnet.prober.icmp6_error._closed_udp_port", return_value=33434), \
         patch("decnet.prober.icmp6_error._ephemeral", return_value=50000):
        with patch("scapy.sendrecv.sr1", return_value=None):
            result = _probe_hop_limit_exceeded(_TARGET_V6, 0.1, on_link=False)
    assert result["returned"] is False


# ─── elicit_icmp6_errors ──────────────────────────────────────────────────────

def test_elicit_returns_none_when_scapy_unavailable() -> None:
    from decnet.prober.icmp6_error import elicit_icmp6_errors
    import builtins

    real_import = builtins.__import__

    def _import_blocker(name, *args, **kwargs):
        if name.startswith("scapy"):
            raise ImportError(f"mocked: {name}")
        return real_import(name, *args, **kwargs)

    with patch.object(builtins, "__import__", side_effect=_import_blocker):
        result = elicit_icmp6_errors(_TARGET_V6, 0.1)
    assert result is None


def test_elicit_returns_dict_with_all_keys() -> None:
    from decnet.prober.icmp6_error import elicit_icmp6_errors

    silent = dict(_SILENT)
    sent_silent = {**silent, "sent": True}
    with (
        patch("decnet.prober.icmp6_error._probe_port_unreachable_v6", return_value=sent_silent),
        patch("decnet.prober.icmp6_error._probe_hop_limit_exceeded",  return_value=silent),
        patch("decnet.prober.icmp6_error._probe_unknown_next_header", return_value=silent),
        patch("decnet.prober.icmp6_error._probe_bad_dest_option",     return_value=silent),
        patch("decnet.prober.ipv6_leak._route_info", return_value=(False, "eth0")),
    ):
        result = elicit_icmp6_errors(_TARGET_V6, 0.1)

    assert result is not None
    assert set(result.keys()) == {"matrix", "fingerprint_hash", "errors", "observed_at"}
    assert set(result["errors"].keys()) == {
        "port_unreachable_v6", "hop_limit_exceeded", "unknown_next_header", "bad_dest_option"
    }


def test_elicit_returns_none_when_all_silent_no_caps() -> None:
    from decnet.prober.icmp6_error import elicit_icmp6_errors

    silent = dict(_SILENT)  # all sent=False
    with (
        patch("decnet.prober.icmp6_error._probe_port_unreachable_v6", return_value=silent),
        patch("decnet.prober.icmp6_error._probe_hop_limit_exceeded",  return_value=silent),
        patch("decnet.prober.icmp6_error._probe_unknown_next_header", return_value=silent),
        patch("decnet.prober.icmp6_error._probe_bad_dest_option",     return_value=silent),
        patch("decnet.prober.ipv6_leak._route_info", return_value=(False, "eth0")),
    ):
        result = elicit_icmp6_errors(_TARGET_V6, 0.1)

    assert result is None


# ─── hash + matrix purity ─────────────────────────────────────────────────────

def test_fingerprint_hash_stable() -> None:
    from decnet.prober.icmp6_error import _build_matrix, _compute_hash

    errors = {
        "port_unreachable_v6": {"returned": True,  "icmp_code": 4,    "echo_len": 48},
        "hop_limit_exceeded":  {"returned": False, "icmp_code": None, "echo_len": None},
        "unknown_next_header": {"returned": False, "icmp_code": None, "echo_len": None},
        "bad_dest_option":     {"returned": False, "icmp_code": None, "echo_len": None},
    }
    matrix = _build_matrix(errors)  # type: ignore[arg-type]
    h1 = _compute_hash(matrix, errors)  # type: ignore[arg-type]
    h2 = _compute_hash(matrix, errors)  # type: ignore[arg-type]
    assert h1 == h2
    assert len(h1) == 32


def test_matrix_encoding_table() -> None:
    """Matrix encodes presence/absence for all four ICMPv6 primitives correctly."""
    from decnet.prober.icmp6_error import _build_matrix

    def _ret(code: int | None) -> dict[str, Any]:
        return {"returned": True, "icmp_code": code, "echo_len": 8}

    def _sil() -> dict[str, Any]:
        return {"returned": False, "icmp_code": None, "echo_len": None}

    # All silent
    m = _build_matrix({"port_unreachable_v6": _sil(), "hop_limit_exceeded": _sil(), "unknown_next_header": _sil(), "bad_dest_option": _sil()})  # type: ignore[arg-type]
    assert m == "...."

    # All returned with codes
    m = _build_matrix({"port_unreachable_v6": _ret(4), "hop_limit_exceeded": _ret(0), "unknown_next_header": _ret(1), "bad_dest_option": _ret(2)})  # type: ignore[arg-type]
    assert m == "UHNB"

    # Mixed — first and third returned
    m = _build_matrix({"port_unreachable_v6": _ret(4), "hop_limit_exceeded": _sil(), "unknown_next_header": _ret(1), "bad_dest_option": _sil()})  # type: ignore[arg-type]
    assert m == "U.N."

    # Returned but code is None → '~'
    m = _build_matrix({"port_unreachable_v6": _ret(None), "hop_limit_exceeded": _sil(), "unknown_next_header": _sil(), "bad_dest_option": _sil()})  # type: ignore[arg-type]
    assert m == "~..."


# ─── metaclass registration ───────────────────────────────────────────────────

def test_icmp6_error_probe_registered() -> None:
    import decnet.prober.probes  # noqa: F401 — triggers registration
    from decnet.prober.base import ActiveProbeMeta
    names = {cls.probe_name for cls in ActiveProbeMeta.all()}
    assert "icmp6_error" in names
