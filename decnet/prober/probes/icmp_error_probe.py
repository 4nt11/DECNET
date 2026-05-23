# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from typing import Any

from decnet.logging import get_logger
from decnet.prober.base import ActiveProbe

_log = get_logger("prober.icmp_error_probe")


class IcmpErrorProbe(ActiveProbe):
    """Port-free probe that elicits ICMP error replies from the attacker.

    Sends four crafted stimuli (UDP/closed-port, TTL=1, DF+oversized, bad
    IP option) and records which ICMP error classes the target emits, the
    per-error RTT, and bytes echoed back in each ICMP error body.

    Silent responses are as fingerprint-worthy as replies: Linux emits at
    most 1 ICMP error/sec, so rate-limited absences reveal OS behaviour.

    Requires root / CAP_NET_RAW. Scapy is lazy-imported inside the helper.
    """

    probe_name = "icmp_error"
    default_ports: list[int | None] = [None]
    event_type = "icmp_error_leak"
    priority = 850  # after TCP/TLS (100-200), before ipv6_leak (999)

    def run(self, ip: str, port: int | None, timeout: float) -> dict[str, Any] | None:
        from decnet.prober.icmp_error import elicit_icmp_errors
        return elicit_icmp_errors(ip, timeout=timeout)

    def syslog_fields(
        self, ip: str, port: int | None, result: dict[str, Any]
    ) -> tuple[dict[str, Any], str]:
        matrix = result.get("matrix", "")
        fp_hash = result.get("fingerprint_hash", "")
        errors = result.get("errors", {})

        def _flag(key: str) -> str:
            return "1" if errors.get(key, {}).get("returned", False) else "0"

        def _rtt(key: str) -> str:
            v = errors.get(key, {}).get("rtt_ms")
            return str(v) if v is not None else ""

        fields: dict[str, Any] = {
            "icmp_matrix":               matrix,
            "icmp_fp_hash":              fp_hash,
            "icmp_port_unreach":         _flag("port_unreachable"),
            "icmp_time_exceeded":        _flag("time_exceeded"),
            "icmp_frag_needed":          _flag("frag_needed"),
            "icmp_param_problem":        _flag("param_problem"),
            "icmp_port_unreach_rtt_ms":  _rtt("port_unreachable"),
            "icmp_time_exceeded_rtt_ms": _rtt("time_exceeded"),
            "icmp_frag_needed_rtt_ms":   _rtt("frag_needed"),
            "icmp_param_problem_rtt_ms": _rtt("param_problem"),
            "icmp_time_exceeded_hop":    errors.get("time_exceeded", {}).get("src_ip") or "",
        }
        msg = f"ICMP leak {ip} → matrix={matrix} fp={fp_hash[:8]}"
        return fields, msg

    def publish_payload(
        self, ip: str, port: int | None, result: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "attacker_ip":    ip,
            "icmp_matrix":    result.get("matrix", ""),
            "icmp_fp_hash":   result.get("fingerprint_hash", ""),
            "errors":         result.get("errors", {}),
            "observed_at":    result.get("observed_at", ""),
        }
