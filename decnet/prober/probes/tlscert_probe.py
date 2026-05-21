from __future__ import annotations

from typing import Any

from decnet.prober.base import ActiveProbe
from decnet.prober.tlscert import fetch_leaf_cert
from decnet.telemetry import traced as _traced

DEFAULT_PORTS: list[int | None] = [443, 8443, 8080, 4443, 50050, 2222, 993, 995, 8888, 9001]


class TlsCertProbe(ActiveProbe):
    """Fetch the leaf TLS certificate from attacker-run servers.

    Runs after JarmProbe (priority=200 > 100) on the same port set.
    Returns None when the port does not speak TLS — no event emitted.
    """

    probe_name = "tls_certificate"
    default_ports: list[int | None] = DEFAULT_PORTS
    event_type = "tls_certificate"
    rotation_type = None
    rotation_hash_key = None
    priority = 200

    @_traced("prober.tls_cert_probe")
    def run(self, ip: str, port: int | None, timeout: float) -> dict[str, Any] | None:
        if port is None:
            return None
        return fetch_leaf_cert(ip, port, timeout=timeout)

    def syslog_fields(self, ip: str, port: int | None, result: dict[str, Any]) -> tuple[dict[str, Any], str]:
        fields = {
            "subject_cn": result["subject_cn"],
            "issuer": result["issuer"],
            "self_signed": str(result["self_signed"]).lower(),
            "not_before": result["not_before"],
            "not_after": result["not_after"],
            "sans": ",".join(result["sans"]),
            "cert_sha256": result["cert_sha256"],
        }
        msg = f"TLS cert {ip}:{port} CN={result['subject_cn']} sha256={result['cert_sha256'][:16]}..."
        return fields, msg

    def publish_payload(self, ip: str, port: int | None, result: dict[str, Any]) -> dict[str, Any]:
        return {
            "attacker_ip": ip,
            "port": port,
            "subject_cn": result["subject_cn"],
            "cert_sha256": result["cert_sha256"],
            "self_signed": result["self_signed"],
        }
