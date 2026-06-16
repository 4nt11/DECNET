# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from typing import Any

from decnet.prober.base import ActiveProbe
from decnet.prober.hassh import hassh_server
from decnet.telemetry import traced as _traced

DEFAULT_PORTS: list[int | None] = [22, 2222, 22222, 2022]


class HasshProbe(ActiveProbe):
    probe_name = "hassh"
    default_ports: list[int | None] = DEFAULT_PORTS
    event_type = "hassh_fingerprint"
    rotation_type = "hassh"
    rotation_hash_key = "hassh_server"
    priority = 100

    @_traced("prober.hassh_probe")
    def run(self, ip: str, port: int | None, timeout: float) -> dict[str, Any] | None:
        if port is None:
            return None
        return hassh_server(ip, port, timeout=timeout)

    def syslog_fields(self, ip: str, port: int | None, result: dict[str, Any]) -> tuple[dict[str, Any], str]:
        fields = {
            "hassh_server_hash": result["hassh_server"],
            "ssh_banner": result["banner"],
            "kex_algorithms": result["kex_algorithms"],
            "encryption_s2c": result["encryption_s2c"],
            "mac_s2c": result["mac_s2c"],
            "compression_s2c": result["compression_s2c"],
        }
        return fields, f"HASSH {ip}:{port} = {result['hassh_server']}"

    def publish_payload(self, ip: str, port: int | None, result: dict[str, Any]) -> dict[str, Any]:
        return {
            "attacker_ip": ip,
            "port": port,
            "hassh_server": result["hassh_server"],
            "ssh_banner": result["banner"],
        }
