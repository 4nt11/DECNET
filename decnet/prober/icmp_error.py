# SPDX-License-Identifier: AGPL-3.0-or-later
"""ICMP error-elicitation prober.

Sends four crafted stimuli to a target and records which ICMP error
classes are returned, the per-error RTT, and the bytes echoed back inside
each ICMP error body. Silence is as informative as a reply — Linux emits
at most 1 ICMP error/sec by default, so rate-limited absences are
fingerprint-worthy too.

Requires root / CAP_NET_RAW. Scapy is lazy-imported so non-root callers
of other prober modules are not broken.
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timezone
from typing import Any

from decnet.logging import get_logger
from decnet.telemetry import traced as _traced

_log = get_logger("prober.icmp_error")

# ─── per-primitive result shape ──────────────────────────────────────────────
# {
#   "returned": bool,
#   "rtt_ms":   float | None,
#   "src_ip":   str   | None,  # sender of the ICMP error (may differ from target)
#   "icmp_code": int  | None,
#   "echo_len":  int  | None,  # bytes the ICMP body echoed back from our probe
#   "echo_bytes_hex": str | None,
# }

_SILENT: dict[str, Any] = {
    "sent": False,       # False when PermissionError blocked sr1 (no CAP_NET_RAW)
    "returned": False,
    "rtt_ms": None,
    "src_ip": None,
    "icmp_code": None,
    "echo_len": None,
    "echo_bytes_hex": None,
}

# Matrix letter codes: uppercase if returned, '.' if silent, '~' if wrong type
_MATRIX_LETTERS = {
    "port_unreachable": "P",
    "time_exceeded":    "T",
    "frag_needed":      "F",
    "param_problem":    "X",
}


# ─── helpers ──────────────────────────────────────────────────────────────────

def _ephemeral() -> int:
    return random.randint(49152, 65535)  # nosec B311 — ephemeral port, not crypto


def _closed_udp_port() -> int:
    # traceroute range — blends with normal network probing traffic
    return random.randint(33434, 33534)  # nosec B311


def _parse_reply(resp: Any, expected_type: int, expected_code: int | None, start_ns: int) -> dict[str, Any]:
    """Extract a per-primitive result dict from a scapy ICMP reply."""
    from scapy.all import ICMP, IP  # type: ignore[attr-defined]

    rtt_ms: float | None = None
    try:
        rtt_ms = round((resp.time - start_ns) * 1000, 3)
    except Exception as exc:
        _log.debug("icmp_error: rtt extraction failed: %s", exc)

    result: dict[str, Any] = {"sent": True}  # we made it past sr1
    src_ip: str | None = None
    try:
        src_ip = resp[IP].src
    except Exception as exc:
        _log.debug("icmp_error: src_ip extraction failed: %s", exc)

    icmp_code: int | None = None
    echo_len: int | None = None
    echo_bytes_hex: str | None = None

    try:
        icmp_layer = resp[ICMP]
        icmp_code = int(icmp_layer.code)

        # ICMP error bodies echo the original IP header + first 8 bytes of transport.
        payload = bytes(icmp_layer.payload)
        if payload:
            echo_len = len(payload)
            echo_bytes_hex = payload[:32].hex()
    except Exception as exc:
        _log.debug("icmp_error: ICMP field extraction failed: %s", exc)

    wrong_type = False
    try:
        icmp_type = int(resp[ICMP].type)
        wrong_type = icmp_type != expected_type or (
            expected_code is not None and icmp_code != expected_code
        )
    except Exception:
        wrong_type = True

    result.update({
        "returned": not wrong_type,
        "rtt_ms": rtt_ms,
        "src_ip": src_ip,
        "icmp_code": icmp_code,
        "echo_len": echo_len,
        "echo_bytes_hex": echo_bytes_hex,
    })
    return result


# ─── four stimulus primitives ─────────────────────────────────────────────────

@_traced("prober.icmp_error.port_unreachable")
def _probe_port_unreachable(target_ip: str, timeout: float) -> dict[str, Any]:
    """UDP to a closed port → expect ICMP type=3 code=3 (Port Unreachable)."""
    try:
        from scapy.all import IP, Raw, UDP, conf, sr1  # type: ignore[attr-defined]
        import time as _time

        conf.verb = 0
        dport = _closed_udp_port()
        pkt = IP(dst=target_ip) / UDP(sport=_ephemeral(), dport=dport) / Raw(b"\x00" * 32)
        t0 = _time.monotonic()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return dict(_SILENT)
        resp.time = _time.monotonic() - t0
        return _parse_reply(resp, expected_type=3, expected_code=3, start_ns=0)
    except (OSError, PermissionError) as exc:
        _log.debug("icmp_error: port_unreachable probe failed for %s: %s", target_ip, exc)
        return dict(_SILENT)


@_traced("prober.icmp_error.time_exceeded")
def _probe_time_exceeded(
    target_ip: str,
    timeout: float,
    on_link: bool = False,
) -> dict[str, Any]:
    """UDP with ttl=1 → expect ICMP type=11 code=0 (Time Exceeded) from next-hop.

    Skipped when the attacker is on-link (no intermediate hop to probe).
    `on_link` is pre-computed by the caller to avoid a redundant route lookup.
    """
    if on_link:
        return dict(_SILENT)
    try:
        from scapy.all import IP, Raw, UDP, conf, sr1  # type: ignore[attr-defined]
        import time as _time

        conf.verb = 0
        dport = _closed_udp_port()
        pkt = IP(dst=target_ip, ttl=1) / UDP(sport=_ephemeral(), dport=dport) / Raw(b"\x00" * 32)
        t0 = _time.monotonic()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return dict(_SILENT)
        resp.time = _time.monotonic() - t0
        return _parse_reply(resp, expected_type=11, expected_code=0, start_ns=0)
    except (OSError, PermissionError) as exc:
        _log.debug("icmp_error: time_exceeded probe failed for %s: %s", target_ip, exc)
        return dict(_SILENT)


@_traced("prober.icmp_error.frag_needed")
def _probe_frag_needed(target_ip: str, timeout: float) -> dict[str, Any]:
    """Oversized UDP with DF=1 → expect ICMP type=3 code=4 (Fragmentation Needed)."""
    try:
        from scapy.all import IP, Raw, UDP, conf, sr1  # type: ignore[attr-defined]
        import time as _time

        conf.verb = 0
        # 1500 bytes payload forces fragmentation when DF is set
        pkt = (
            IP(dst=target_ip, flags="DF")
            / UDP(sport=_ephemeral(), dport=_closed_udp_port())
            / Raw(b"\x00" * 1500)
        )
        t0 = _time.monotonic()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return dict(_SILENT)
        resp.time = _time.monotonic() - t0
        return _parse_reply(resp, expected_type=3, expected_code=4, start_ns=0)
    except (OSError, PermissionError) as exc:
        _log.debug("icmp_error: frag_needed probe failed for %s: %s", target_ip, exc)
        return dict(_SILENT)


@_traced("prober.icmp_error.param_problem")
def _probe_param_problem(target_ip: str, timeout: float) -> dict[str, Any]:
    """IP packet with malformed option → expect ICMP type=12 (Parameter Problem).

    Most stacks silently drop malformed options; absence is still a fingerprint.
    """
    try:
        from scapy.all import IP, Raw, UDP, conf, sr1  # type: ignore[attr-defined]
        import time as _time

        conf.verb = 0
        # Option class=0 (control), number=17 (MTU probe, often unrecognised),
        # length byte deliberately wrong (2 instead of a valid even value).
        bad_opt = b"\x91\x02"  # type=0x91 (copied flag + class 0 + number 17), len=2
        pkt = (
            IP(dst=target_ip, options=bad_opt)
            / UDP(sport=_ephemeral(), dport=_closed_udp_port())
            / Raw(b"\x00" * 8)
        )
        t0 = _time.monotonic()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return dict(_SILENT)
        resp.time = _time.monotonic() - t0
        return _parse_reply(resp, expected_type=12, expected_code=None, start_ns=0)
    except (OSError, PermissionError) as exc:
        _log.debug("icmp_error: param_problem probe failed for %s: %s", target_ip, exc)
        return dict(_SILENT)


# ─── matrix + hash ────────────────────────────────────────────────────────────

def _build_matrix(errors: dict[str, dict[str, Any]]) -> str:
    parts = []
    for key, letter in _MATRIX_LETTERS.items():
        e = errors.get(key, _SILENT)
        if not e.get("returned", False):
            parts.append(".")
        elif e.get("icmp_code") is not None:
            parts.append(letter)
        else:
            parts.append("~")
    return "".join(parts)


def _compute_hash(matrix: str, errors: dict[str, dict[str, Any]]) -> str:
    echo_lens = tuple(
        errors.get(k, _SILENT).get("echo_len") or 0
        for k in _MATRIX_LETTERS
    )
    icmp_codes = tuple(
        errors.get(k, _SILENT).get("icmp_code") or -1
        for k in _MATRIX_LETTERS
    )
    raw = f"{matrix}:{echo_lens}:{icmp_codes}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# ─── public API ───────────────────────────────────────────────────────────────

@_traced("prober.icmp_error.elicit")
def elicit_icmp_errors(
    target_ip: str,
    timeout: float = 2.0,
) -> dict[str, Any] | None:
    """Send four ICMP-eliciting probes and return a fingerprint result dict.

    Returns None when scapy is unavailable or all four primitives produced
    no information (all silent with no exception — pure silence is still
    fingerprint-worthy, but we need at least one probe to have executed
    without a hard error before returning a result).

    Requires root / CAP_NET_RAW.
    """
    try:
        import scapy.all  # noqa: F401 — presence check
    except ImportError:
        _log.debug("scapy not available — icmp_error active probe skipped")
        return None

    # Pre-compute on-link status once for the time_exceeded gate.
    on_link = False
    try:
        from decnet.prober.ipv6_leak import _route_info
        on_link, _ = _route_info(target_ip)
    except Exception as exc:
        _log.debug("icmp_error: _route_info failed for %s: %s", target_ip, exc)

    errors: dict[str, dict[str, Any]] = {
        "port_unreachable": _probe_port_unreachable(target_ip, timeout),
        "time_exceeded":    _probe_time_exceeded(target_ip, timeout, on_link=on_link),
        "frag_needed":      _probe_frag_needed(target_ip, timeout),
        "param_problem":    _probe_param_problem(target_ip, timeout),
    }

    if not any(e.get("sent", False) for e in errors.values()):
        _log.debug("icmp_error: no packets sent to %s (no CAP_NET_RAW?)", target_ip)
        return None

    matrix = _build_matrix(errors)
    fp_hash = _compute_hash(matrix, errors)

    return {
        "matrix": matrix,
        "fingerprint_hash": fp_hash,
        "errors": errors,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
