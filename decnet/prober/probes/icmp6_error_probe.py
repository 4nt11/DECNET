from __future__ import annotations

import ipaddress
from typing import Any

from decnet.logging import get_logger
from decnet.prober.base import ActiveProbe

_log = get_logger("prober.icmp6_error_probe")


class Icmp6ErrorProbe(ActiveProbe):
    """Port-free probe that elicits ICMPv6 error replies from an IPv6 attacker.

    Sends four crafted stimuli (UDP/closed-port, hlim=1, unknown NH=253,
    bad destination option type=0x80) and records which ICMPv6 error classes
    the target emits, per-error RTT, and bytes echoed back in each error body.

    Returns None immediately for IPv4 attacker IPs — those are handled by
    IcmpErrorProbe.

    Requires root / CAP_NET_RAW. Scapy is lazy-imported inside the helper.
    """

    probe_name = "icmp6_error"
    default_ports: list[int | None] = [None]
    event_type = "icmp6_error_leak"
    priority = 860  # after icmp_error (850), before ipv6_leak (999)

    def run(self, ip: str, port: int | None, timeout: float) -> dict[str, Any] | None:
        try:
            if ipaddress.ip_address(ip).version != 6:
                return None
        except ValueError:
            return None
        from decnet.prober.icmp6_error import elicit_icmp6_errors
        return elicit_icmp6_errors(ip, timeout=timeout)

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
            "icmp6_matrix":                     matrix,
            "icmp6_fp_hash":                    fp_hash,
            "icmp6_port_unreach":               _flag("port_unreachable_v6"),
            "icmp6_hop_limit_exceeded":         _flag("hop_limit_exceeded"),
            "icmp6_unknown_next_header":        _flag("unknown_next_header"),
            "icmp6_bad_dest_option":            _flag("bad_dest_option"),
            "icmp6_port_unreach_rtt_ms":        _rtt("port_unreachable_v6"),
            "icmp6_hop_limit_exceeded_rtt_ms":  _rtt("hop_limit_exceeded"),
            "icmp6_unknown_next_header_rtt_ms": _rtt("unknown_next_header"),
            "icmp6_bad_dest_option_rtt_ms":     _rtt("bad_dest_option"),
            "icmp6_hop_limit_exceeded_hop":     errors.get("hop_limit_exceeded", {}).get("src_ip") or "",
        }
        msg = f"ICMPv6 leak {ip} → matrix={matrix} fp={fp_hash[:8]}"
        return fields, msg

    def publish_payload(
        self, ip: str, port: int | None, result: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "attacker_ip":   ip,
            "icmp6_matrix":  result.get("matrix", ""),
            "icmp6_fp_hash": result.get("fingerprint_hash", ""),
            "errors":        result.get("errors", {}),
            "observed_at":   result.get("observed_at", ""),
        }
