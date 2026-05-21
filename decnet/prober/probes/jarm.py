from __future__ import annotations

from typing import Any

from decnet.prober.base import ActiveProbe
from decnet.prober.jarm import JARM_EMPTY_HASH, jarm_hash
from decnet.telemetry import traced as _traced

DEFAULT_PORTS: list[int | None] = [443, 8443, 8080, 4443, 50050, 2222, 993, 995, 8888, 9001]


class JarmProbe(ActiveProbe):
    probe_name = "jarm"
    default_ports: list[int | None] = DEFAULT_PORTS
    event_type = "jarm_fingerprint"
    rotation_type = "jarm"
    rotation_hash_key = "jarm_hash"
    priority = 100

    @_traced("prober.jarm_probe")
    def run(self, ip: str, port: int | None, timeout: float) -> dict[str, Any] | None:
        if port is None:
            return None
        h = jarm_hash(ip, port, timeout=timeout)
        if h == JARM_EMPTY_HASH:
            return None
        return {"jarm_hash": h}

    def syslog_fields(self, ip: str, port: int | None, result: dict[str, Any]) -> tuple[dict[str, Any], str]:
        h = result["jarm_hash"]
        return {"jarm_hash": h}, f"JARM {ip}:{port} = {h}"

    def publish_payload(self, ip: str, port: int | None, result: dict[str, Any]) -> dict[str, Any]:
        return {"attacker_ip": ip, "port": port, "jarm_hash": result["jarm_hash"]}
