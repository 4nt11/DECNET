from __future__ import annotations

from typing import Any

from decnet.prober.base import ActiveProbe
from decnet.prober.tcpfp import tcp_fingerprint
from decnet.telemetry import traced as _traced

DEFAULT_PORTS: list[int | None] = [22, 80, 443, 8080, 8443, 445, 3389]


class TcpfpProbe(ActiveProbe):
    probe_name = "tcpfp"
    default_ports: list[int | None] = DEFAULT_PORTS
    event_type = "tcpfp_fingerprint"
    rotation_type = "tcpfp"
    rotation_hash_key = "tcpfp_hash"
    priority = 100

    @_traced("prober.tcpfp_probe")
    def run(self, ip: str, port: int | None, timeout: float) -> dict[str, Any] | None:
        if port is None:
            return None
        return tcp_fingerprint(ip, port, timeout=timeout)

    def syslog_fields(self, ip: str, port: int | None, result: dict[str, Any]) -> tuple[dict[str, Any], str]:
        fields = {
            "tcpfp_hash": result["tcpfp_hash"],
            "tcpfp_raw": result["tcpfp_raw"],
            "ttl": str(result["ttl"]),
            "window_size": str(result["window_size"]),
            "df_bit": str(result["df_bit"]),
            "mss": str(result["mss"]),
            "window_scale": str(result["window_scale"]),
            "sack_ok": str(result["sack_ok"]),
            "timestamp": str(result["timestamp"]),
            "options_order": result["options_order"],
            "tos": str(result["tos"]),
            "dscp": str(result["dscp"]),
            "ecn": str(result["ecn"]),
            "server_isn": str(result["server_isn"]),
        }
        return fields, f"TCPFP {ip}:{port} = {result['tcpfp_hash']}"

    def publish_payload(self, ip: str, port: int | None, result: dict[str, Any]) -> dict[str, Any]:
        return {
            "attacker_ip": ip,
            "port": port,
            "tcpfp_hash": result["tcpfp_hash"],
            "ttl": result["ttl"],
            "mss": result["mss"],
        }
