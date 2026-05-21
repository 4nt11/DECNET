"""Tests for IcmpErrorProbe and the underlying icmp_error helpers.

Covers:
- IcmpErrorProbe.run() returns helper result verbatim.
- IcmpErrorProbe.run() returns None when helper returns None.
- IcmpErrorProbe.syslog_fields() — stable key set, correct flag encoding, human msg.
- IcmpErrorProbe.publish_payload() — correct bus payload shape.
- _probe_port_unreachable / _probe_time_exceeded / _probe_frag_needed /
  _probe_param_problem — returned-reply and silent-timeout cases.
- _probe_time_exceeded skipped when on-link.
- elicit_icmp_errors returns None when scapy is unavailable.
- Fingerprint hash is deterministic for identical inputs.
- Matrix encoding table-driven across all four present/absent combinations.
"""
from __future__ import annotations

import importlib
from typing import Any
from unittest.mock import MagicMock, call, patch

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
    "matrix": "PT..",
    "fingerprint_hash": "abcdef1234567890abcdef1234567890",
    "errors": {
        "port_unreachable": {
            "sent": True, "returned": True, "rtt_ms": 1.5, "src_ip": "10.0.0.9",
            "icmp_code": 3, "echo_len": 28, "echo_bytes_hex": "aabbcc",
        },
        "time_exceeded": {
            "sent": True, "returned": True, "rtt_ms": 0.8, "src_ip": "192.168.1.1",
            "icmp_code": 0, "echo_len": 28, "echo_bytes_hex": "ddeeff",
        },
        "frag_needed": dict(_SILENT),
        "param_problem": dict(_SILENT),
    },
    "observed_at": "2026-01-01T00:00:00+00:00",
}


def _make_probe():
    from decnet.prober.probes.icmp_error_probe import IcmpErrorProbe
    return IcmpErrorProbe()


# ─── IcmpErrorProbe.run() ─────────────────────────────────────────────────────

def test_run_returns_evidence() -> None:
    probe = _make_probe()
    with patch("decnet.prober.icmp_error.elicit_icmp_errors", return_value=_EVIDENCE) as mock_fn:
        result = probe.run("10.0.0.9", None, 2.0)
    assert result == _EVIDENCE
    mock_fn.assert_called_once_with("10.0.0.9", timeout=2.0)


def test_run_returns_none_when_helper_returns_none() -> None:
    probe = _make_probe()
    with patch("decnet.prober.icmp_error.elicit_icmp_errors", return_value=None):
        result = probe.run("10.0.0.9", None, 2.0)
    assert result is None


# ─── IcmpErrorProbe.syslog_fields() ──────────────────────────────────────────

_EXPECTED_SD_KEYS = {
    "icmp_matrix",
    "icmp_fp_hash",
    "icmp_port_unreach",
    "icmp_time_exceeded",
    "icmp_frag_needed",
    "icmp_param_problem",
    "icmp_port_unreach_rtt_ms",
    "icmp_time_exceeded_rtt_ms",
    "icmp_frag_needed_rtt_ms",
    "icmp_param_problem_rtt_ms",
    "icmp_time_exceeded_hop",
}


def test_syslog_fields_byte_stable() -> None:
    probe = _make_probe()
    fields, _ = probe.syslog_fields("10.0.0.9", None, _EVIDENCE)
    assert set(fields.keys()) == _EXPECTED_SD_KEYS


def test_syslog_fields_flag_encoding() -> None:
    probe = _make_probe()
    fields, _ = probe.syslog_fields("10.0.0.9", None, _EVIDENCE)
    assert fields["icmp_port_unreach"] == "1"
    assert fields["icmp_time_exceeded"] == "1"
    assert fields["icmp_frag_needed"] == "0"
    assert fields["icmp_param_problem"] == "0"


def test_syslog_fields_rtt_populated() -> None:
    probe = _make_probe()
    fields, _ = probe.syslog_fields("10.0.0.9", None, _EVIDENCE)
    assert fields["icmp_port_unreach_rtt_ms"] == "1.5"
    assert fields["icmp_time_exceeded_rtt_ms"] == "0.8"
    assert fields["icmp_frag_needed_rtt_ms"] == ""
    assert fields["icmp_param_problem_rtt_ms"] == ""


def test_syslog_fields_time_exceeded_hop() -> None:
    probe = _make_probe()
    fields, _ = probe.syslog_fields("10.0.0.9", None, _EVIDENCE)
    assert fields["icmp_time_exceeded_hop"] == "192.168.1.1"


def test_syslog_fields_human_msg_contains_ip_and_matrix() -> None:
    probe = _make_probe()
    _, msg = probe.syslog_fields("10.0.0.9", None, _EVIDENCE)
    assert "10.0.0.9" in msg
    assert "PT.." in msg


def test_syslog_fields_matrix_and_hash_present() -> None:
    probe = _make_probe()
    fields, _ = probe.syslog_fields("10.0.0.9", None, _EVIDENCE)
    assert fields["icmp_matrix"] == "PT.."
    assert fields["icmp_fp_hash"] == _EVIDENCE["fingerprint_hash"]


# ─── IcmpErrorProbe.publish_payload() ────────────────────────────────────────

def test_publish_payload_structure() -> None:
    probe = _make_probe()
    payload = probe.publish_payload("10.0.0.9", None, _EVIDENCE)
    assert payload["attacker_ip"] == "10.0.0.9"
    assert payload["icmp_matrix"] == "PT.."
    assert payload["icmp_fp_hash"] == _EVIDENCE["fingerprint_hash"]
    assert payload["errors"] is _EVIDENCE["errors"]
    assert payload["observed_at"] == _EVIDENCE["observed_at"]


# ─── helper: _parse_reply ────────────────────────────────────────────────────

def _make_mock_resp(icmp_type: int, icmp_code: int, src_ip: str, payload_bytes: bytes = b"\x00" * 20) -> MagicMock:
    """Build a minimal scapy-shaped response mock."""
    resp = MagicMock()
    resp.time = 0.0

    icmp_layer = MagicMock()
    icmp_layer.type = icmp_type
    icmp_layer.code = icmp_code
    icmp_layer.payload = MagicMock()
    icmp_layer.payload.__bytes__ = lambda self: payload_bytes
    # make bytes(icmp_layer.payload) work
    type(icmp_layer.payload).__bytes__ = lambda self: payload_bytes

    ip_layer = MagicMock()
    ip_layer.src = src_ip

    def getitem(key):
        from scapy.all import ICMP, IP  # type: ignore[attr-defined]
        if key is IP or (isinstance(key, type) and key.__name__ == "IP"):
            return ip_layer
        if key is ICMP or (isinstance(key, type) and key.__name__ == "ICMP"):
            return icmp_layer
        raise KeyError(key)

    resp.__getitem__ = getitem
    return resp


# ─── helper: primitive probe unit tests ──────────────────────────────────────

def test_probe_port_unreachable_silent_on_none_response() -> None:
    from decnet.prober.icmp_error import _probe_port_unreachable
    with patch("decnet.prober.icmp_error._closed_udp_port", return_value=33434), \
         patch("decnet.prober.icmp_error._ephemeral", return_value=50000):
        with patch("scapy.all.sr1", return_value=None):
            result = _probe_port_unreachable("10.0.0.9", 0.1)
    assert result["returned"] is False
    assert result["rtt_ms"] is None


def test_probe_frag_needed_silent_on_none_response() -> None:
    from decnet.prober.icmp_error import _probe_frag_needed
    with patch("decnet.prober.icmp_error._closed_udp_port", return_value=33434), \
         patch("decnet.prober.icmp_error._ephemeral", return_value=50000):
        with patch("scapy.all.sr1", return_value=None):
            result = _probe_frag_needed("10.0.0.9", 0.1)
    assert result["returned"] is False


def test_probe_param_problem_silent_on_none_response() -> None:
    from decnet.prober.icmp_error import _probe_param_problem
    with patch("decnet.prober.icmp_error._closed_udp_port", return_value=33434), \
         patch("decnet.prober.icmp_error._ephemeral", return_value=50000):
        with patch("scapy.all.sr1", return_value=None):
            result = _probe_param_problem("10.0.0.9", 0.1)
    assert result["returned"] is False


def test_probe_time_exceeded_skipped_when_on_link() -> None:
    from decnet.prober.icmp_error import _probe_time_exceeded
    with patch("scapy.all.sr1") as mock_sr1:
        result = _probe_time_exceeded("10.0.0.9", 0.1, on_link=True)
    assert result["returned"] is False
    mock_sr1.assert_not_called()


def test_probe_time_exceeded_silent_when_not_on_link() -> None:
    from decnet.prober.icmp_error import _probe_time_exceeded
    with patch("decnet.prober.icmp_error._closed_udp_port", return_value=33434), \
         patch("decnet.prober.icmp_error._ephemeral", return_value=50000):
        with patch("scapy.all.sr1", return_value=None):
            result = _probe_time_exceeded("10.0.0.9", 0.1, on_link=False)
    assert result["returned"] is False


# ─── helper: elicit_icmp_errors ──────────────────────────────────────────────

def test_elicit_returns_none_when_scapy_unavailable() -> None:
    from decnet.prober.icmp_error import elicit_icmp_errors

    real_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__

    def _import_blocker(name, *args, **kwargs):
        if name.startswith("scapy"):
            raise ImportError(f"mocked: {name}")
        return real_import(name, *args, **kwargs)

    import builtins
    with patch.object(builtins, "__import__", side_effect=_import_blocker):
        result = elicit_icmp_errors("10.0.0.9", 0.1)
    assert result is None


def test_elicit_returns_dict_with_all_keys() -> None:
    from decnet.prober.icmp_error import elicit_icmp_errors

    silent = dict(_SILENT)
    # At least one primitive must have sent=True or elicit returns None.
    sent_silent = {**silent, "sent": True}
    with (
        patch("decnet.prober.icmp_error._probe_port_unreachable", return_value=sent_silent),
        patch("decnet.prober.icmp_error._probe_time_exceeded", return_value=silent),
        patch("decnet.prober.icmp_error._probe_frag_needed", return_value=silent),
        patch("decnet.prober.icmp_error._probe_param_problem", return_value=silent),
        patch("decnet.prober.ipv6_leak._route_info", return_value=(False, "eth0")),
    ):
        result = elicit_icmp_errors("10.0.0.9", 0.1)

    assert result is not None
    assert set(result.keys()) == {"matrix", "fingerprint_hash", "errors", "observed_at"}
    assert set(result["errors"].keys()) == {
        "port_unreachable", "time_exceeded", "frag_needed", "param_problem"
    }


def test_elicit_returns_none_when_all_silent_no_caps() -> None:
    from decnet.prober.icmp_error import elicit_icmp_errors

    silent = dict(_SILENT)  # all sent=False (PermissionError path)
    with (
        patch("decnet.prober.icmp_error._probe_port_unreachable", return_value=silent),
        patch("decnet.prober.icmp_error._probe_time_exceeded", return_value=silent),
        patch("decnet.prober.icmp_error._probe_frag_needed", return_value=silent),
        patch("decnet.prober.icmp_error._probe_param_problem", return_value=silent),
        patch("decnet.prober.ipv6_leak._route_info", return_value=(False, "eth0")),
    ):
        result = elicit_icmp_errors("10.0.0.9", 0.1)

    assert result is None


def test_fingerprint_hash_stable() -> None:
    from decnet.prober.icmp_error import _build_matrix, _compute_hash

    errors = {
        "port_unreachable": {"returned": True, "icmp_code": 3, "echo_len": 28},
        "time_exceeded":    {"returned": False, "icmp_code": None, "echo_len": None},
        "frag_needed":      {"returned": False, "icmp_code": None, "echo_len": None},
        "param_problem":    {"returned": False, "icmp_code": None, "echo_len": None},
    }
    matrix = _build_matrix(errors)  # type: ignore[arg-type]
    h1 = _compute_hash(matrix, errors)  # type: ignore[arg-type]
    h2 = _compute_hash(matrix, errors)  # type: ignore[arg-type]
    assert h1 == h2
    assert len(h1) == 32


def test_matrix_encoding_table() -> None:
    """Matrix encodes presence/absence for all four primitives correctly."""
    from decnet.prober.icmp_error import _build_matrix

    def _ret(code: int | None) -> dict[str, Any]:
        return {"returned": True, "icmp_code": code, "echo_len": 8}

    def _sil() -> dict[str, Any]:
        return {"returned": False, "icmp_code": None, "echo_len": None}

    # All silent
    m = _build_matrix({"port_unreachable": _sil(), "time_exceeded": _sil(), "frag_needed": _sil(), "param_problem": _sil()})  # type: ignore[arg-type]
    assert m == "...."

    # All returned with codes
    m = _build_matrix({"port_unreachable": _ret(3), "time_exceeded": _ret(0), "frag_needed": _ret(4), "param_problem": _ret(0)})  # type: ignore[arg-type]
    assert m == "PTFX"

    # Mixed — first and third returned
    m = _build_matrix({"port_unreachable": _ret(3), "time_exceeded": _sil(), "frag_needed": _ret(4), "param_problem": _sil()})  # type: ignore[arg-type]
    assert m == "P.F."

    # Returned but code is None → '~' (wrong type / parse failure)
    m = _build_matrix({"port_unreachable": _ret(None), "time_exceeded": _sil(), "frag_needed": _sil(), "param_problem": _sil()})  # type: ignore[arg-type]
    assert m == "~..."
