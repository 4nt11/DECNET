# SPDX-License-Identifier: AGPL-3.0-or-later
"""ICMPv6 error-elicitation prober.

Sends four crafted stimuli to a target and records which ICMPv6 error
classes are returned, the per-error RTT, and the bytes echoed back inside
each ICMPv6 error body. Silence is as informative as a reply.

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

_log = get_logger("prober.icmp6_error")

# ─── per-primitive result shape ──────────────────────────────────────────────
# {
#   "returned": bool,
#   "rtt_ms":   float | None,
#   "src_ip":   str   | None,  # sender of the ICMPv6 error (may differ from target)
#   "icmp_code": int  | None,
#   "echo_len":  int  | None,  # bytes the ICMPv6 body echoed back from our probe
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
    "port_unreachable_v6": "U",
    "hop_limit_exceeded":  "H",
    "unknown_next_header": "N",
    "bad_dest_option":     "B",
}


# ─── helpers ──────────────────────────────────────────────────────────────────

def _ephemeral() -> int:
    return random.randint(49152, 65535)  # nosec B311 — ephemeral port, not crypto


def _closed_udp_port() -> int:
    return random.randint(33434, 33534)  # nosec B311


def _parse_reply_v6(
    resp: Any,
    expected_type: int,
    expected_code: int | None,
) -> dict[str, Any]:
    """Extract a per-primitive result dict from a scapy ICMPv6 error reply."""
    from scapy.layers.inet6 import (
        ICMPv6DestUnreach,
        ICMPv6ParamProblem,
        ICMPv6TimeExceeded,
        IPv6,
    )

    rtt_ms: float | None = None
    try:
        rtt_ms = round(resp.time * 1000, 3)
    except Exception as exc:
        _log.debug("icmp6_error: rtt extraction failed: %s", exc)

    result: dict[str, Any] = {"sent": True}
    src_ip: str | None = None
    try:
        src_ip = resp[IPv6].src
    except Exception as exc:
        _log.debug("icmp6_error: src_ip extraction failed: %s", exc)

    icmp_code: int | None = None
    echo_len: int | None = None
    echo_bytes_hex: str | None = None
    actual_type: int | None = None

    for t, cls in (
        (1, ICMPv6DestUnreach),
        (3, ICMPv6TimeExceeded),
        (4, ICMPv6ParamProblem),
    ):
        if resp.haslayer(cls):
            actual_type = t
            try:
                layer = resp[cls]
                icmp_code = int(layer.code)
                payload = bytes(layer.payload)
                if payload:
                    echo_len = len(payload)
                    echo_bytes_hex = payload[:32].hex()
            except Exception as exc:
                _log.debug("icmp6_error: ICMPv6 field extraction failed: %s", exc)
            break

    wrong_type = (
        actual_type is None
        or actual_type != expected_type
        or (expected_code is not None and icmp_code != expected_code)
    )

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

@_traced("prober.icmp6_error.port_unreachable_v6")
def _probe_port_unreachable_v6(target_ip: str, timeout: float) -> dict[str, Any]:
    """UDP to a closed port → expect ICMPv6 type=1 code=4 (Port Unreachable)."""
    try:
        from scapy.layers.inet6 import IPv6, UDP
        from scapy.packet import Raw
        from scapy.sendrecv import sr1
        import time as _time

        pkt = IPv6(dst=target_ip) / UDP(sport=_ephemeral(), dport=_closed_udp_port()) / Raw(b"\x00" * 32)
        t0 = _time.monotonic()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return dict(_SILENT)
        resp.time = _time.monotonic() - t0
        return _parse_reply_v6(resp, expected_type=1, expected_code=4)
    except (OSError, PermissionError) as exc:
        _log.debug("icmp6_error: port_unreachable_v6 probe failed for %s: %s", target_ip, exc)
        return dict(_SILENT)


@_traced("prober.icmp6_error.hop_limit_exceeded")
def _probe_hop_limit_exceeded(
    target_ip: str,
    timeout: float,
    on_link: bool = False,
) -> dict[str, Any]:
    """UDP with hlim=1 → expect ICMPv6 type=3 code=0 (Hop Limit Exceeded) from next-hop.

    Skipped when the attacker is on-link (no intermediate hop to probe).
    `on_link` is pre-computed by the caller to avoid a redundant route lookup.
    """
    if on_link:
        return dict(_SILENT)
    try:
        from scapy.layers.inet6 import IPv6, UDP
        from scapy.packet import Raw
        from scapy.sendrecv import sr1
        import time as _time

        pkt = IPv6(dst=target_ip, hlim=1) / UDP(sport=_ephemeral(), dport=_closed_udp_port()) / Raw(b"\x00" * 32)
        t0 = _time.monotonic()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return dict(_SILENT)
        resp.time = _time.monotonic() - t0
        return _parse_reply_v6(resp, expected_type=3, expected_code=0)
    except (OSError, PermissionError) as exc:
        _log.debug("icmp6_error: hop_limit_exceeded probe failed for %s: %s", target_ip, exc)
        return dict(_SILENT)


@_traced("prober.icmp6_error.unknown_next_header")
def _probe_unknown_next_header(target_ip: str, timeout: float) -> dict[str, Any]:
    """IPv6 with unrecognised Next Header → expect ICMPv6 type=4 code=1.

    NH=253 (RFC 3692 experimental) forces the target to send Parameter Problem
    code=1 (Unrecognized Next Header type encountered).
    """
    try:
        from scapy.layers.inet6 import IPv6
        from scapy.packet import Raw
        from scapy.sendrecv import sr1
        import time as _time

        pkt = IPv6(dst=target_ip, nh=253) / Raw(b"\x00" * 8)
        t0 = _time.monotonic()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return dict(_SILENT)
        resp.time = _time.monotonic() - t0
        return _parse_reply_v6(resp, expected_type=4, expected_code=1)
    except (OSError, PermissionError) as exc:
        _log.debug("icmp6_error: unknown_next_header probe failed for %s: %s", target_ip, exc)
        return dict(_SILENT)


@_traced("prober.icmp6_error.bad_dest_option")
def _probe_bad_dest_option(target_ip: str, timeout: float) -> dict[str, Any]:
    """Destination option type=0x80 → expect ICMPv6 type=4 code=2.

    Option type high-bits 10xxxxxx = discard + send ICMPv6 error (RFC 2460 §4.2).
    Most stacks silently drop unknown options; absence is still a fingerprint.
    """
    try:
        from scapy.layers.inet6 import HBHOptUnknown, IPv6, IPv6ExtHdrDestOpt, UDP
        from scapy.packet import Raw
        from scapy.sendrecv import sr1
        import time as _time

        # 0x80 = 0b10000000: bits 10 → discard packet + send ICMPv6 to source
        bad_opt = HBHOptUnknown(otype=0x80, optdata=b"\x00\x00\x00\x00")
        pkt = (
            IPv6(dst=target_ip)
            / IPv6ExtHdrDestOpt(options=[bad_opt])
            / UDP(sport=_ephemeral(), dport=_closed_udp_port())
            / Raw(b"\x00" * 8)
        )
        t0 = _time.monotonic()
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return dict(_SILENT)
        resp.time = _time.monotonic() - t0
        return _parse_reply_v6(resp, expected_type=4, expected_code=2)
    except (OSError, PermissionError) as exc:
        _log.debug("icmp6_error: bad_dest_option probe failed for %s: %s", target_ip, exc)
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

@_traced("prober.icmp6_error.elicit")
def elicit_icmp6_errors(
    target_ip: str,
    timeout: float = 2.0,
) -> dict[str, Any] | None:
    """Send four ICMPv6-eliciting probes and return a fingerprint result dict.

    Returns None when scapy inet6 is unavailable or all four primitives
    produced no information (all sent=False, meaning no CAP_NET_RAW).

    Requires root / CAP_NET_RAW. target_ip must be a valid IPv6 address.
    """
    try:
        import scapy.layers.inet6  # noqa: F401 — presence check
    except ImportError:
        _log.debug("scapy inet6 not available — icmp6_error active probe skipped")
        return None

    on_link = False
    try:
        from decnet.prober.ipv6_leak import _route_info
        on_link, _ = _route_info(target_ip)
    except Exception as exc:
        _log.debug("icmp6_error: _route_info failed for %s: %s", target_ip, exc)

    errors: dict[str, dict[str, Any]] = {
        "port_unreachable_v6": _probe_port_unreachable_v6(target_ip, timeout),
        "hop_limit_exceeded":  _probe_hop_limit_exceeded(target_ip, timeout, on_link=on_link),
        "unknown_next_header": _probe_unknown_next_header(target_ip, timeout),
        "bad_dest_option":     _probe_bad_dest_option(target_ip, timeout),
    }

    if not any(e.get("sent", False) for e in errors.values()):
        _log.debug("icmp6_error: no packets sent to %s (no CAP_NET_RAW?)", target_ip)
        return None

    matrix = _build_matrix(errors)
    fp_hash = _compute_hash(matrix, errors)

    return {
        "matrix": matrix,
        "fingerprint_hash": fp_hash,
        "errors": errors,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
