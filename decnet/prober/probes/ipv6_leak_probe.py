# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from typing import Any

from decnet.logging import get_logger
from decnet.prober.base import ActiveProbe

_log = get_logger("prober.ipv6_leak_probe")


class Ipv6LeakProbe(ActiveProbe):
    """Port-free active probe that solicits a fe80:: response from the attacker.

    Sends ICMPv6 Echo Request to ff02::1 on the attacker's reachable iface
    to reveal the attacker's IPv6 IID / MAC-derived address.

    Only fires when the attacker is directly reachable on L2 (no gateway).
    Runs last (priority=999) so all TCP-level probes complete first.
    """

    probe_name = "ipv6_leak"
    default_ports: list[int | None] = [None]
    event_type = "ipv6_link_local_leak"
    priority = 999

    def run(self, ip: str, port: int | None, timeout: float) -> dict[str, Any] | None:
        from decnet.prober.ipv6_leak import _route_info, solicit_ipv6_leak
        on_link, iface = _route_info(ip)
        if not on_link:
            _log.debug("ipv6_leak_probe: %s is not on-link — skip", ip)
            return None
        if iface is None:
            _log.debug("ipv6_leak_probe: cannot determine iface for %s — skip", ip)
            return None
        return solicit_ipv6_leak(ip, iface, timeout=timeout)

    def syslog_fields(
        self, ip: str, port: int | None, result: dict[str, Any]
    ) -> tuple[dict[str, Any], str]:
        addr = result.get("addr", "")
        iid_kind = result.get("iid_kind", "")
        fields = {
            "ipv6_addr": addr,
            "iid_kind": iid_kind,
            "mac_oui": result.get("mac_oui", ""),
            "on_iface": result.get("on_iface", ""),
            "vector": result.get("vector", ""),
        }
        return fields, f"IPv6 leak {ip} → {addr} ({iid_kind})"

    def publish_payload(
        self, ip: str, port: int | None, result: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "attacker_ip": ip,
            "addr": result.get("addr", ""),
            "iid_kind": result.get("iid_kind", ""),
            "mac_oui": result.get("mac_oui", ""),
            "vector": result.get("vector", ""),
            "on_iface": result.get("on_iface", ""),
            "observed_at": result.get("observed_at", ""),
        }
