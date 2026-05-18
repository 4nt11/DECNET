"""Active IPv6 link-local solicitation prober.

Sends ICMPv6 Neighbor Solicitation and Echo Request packets to the
link-local multicast group (ff02::1) on the attacker's reachable iface
to elicit a fe80:: response that reveals the attacker's IID/MAC.

Only useful when the prober shares layer-2 with the attacker (on-link).
The phase function in worker.py gates on this before sending.
"""
from __future__ import annotations

import ipaddress
import subprocess  # nosec B404
from datetime import datetime, timezone
from typing import Any

from decnet.logging import get_logger
from decnet.sniffer.fingerprint import _ipv6_iid_classify

_log = get_logger("prober.ipv6_leak")


def _is_link_local(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_link_local
    except ValueError:
        return False


def _ip_route_get(attacker_v4: str) -> str:
    """Return stdout of `ip route get <attacker_v4>`, or "" on failure."""
    try:
        out = subprocess.run(  # nosec B603 B607
            ["ip", "route", "get", attacker_v4],
            capture_output=True, text=True, timeout=2,
        )
        return out.stdout
    except Exception:
        return ""


def _resolve_iface_for_ip(attacker_v4: str) -> str | None:
    """Return the local interface name that would route to attacker_v4."""
    stdout = _ip_route_get(attacker_v4)
    parts = stdout.split()
    if "dev" in parts:
        idx = parts.index("dev")
        return parts[idx + 1] if idx + 1 < len(parts) else None
    return None


def _is_on_link(attacker_v4: str) -> bool:
    """Return True only when the attacker is directly reachable on L2.

    Checks that `ip route get` shows no intermediate gateway (no "via").
    """
    return "via" not in _ip_route_get(attacker_v4)


def solicit_ipv6_leak(
    attacker_v4: str,
    iface: str,
    timeout: float = 3.0,
) -> dict[str, Any] | None:
    """Send ICMPv6 solicitations on *iface* and return evidence if a
    fe80:: response arrives.

    Returns an ``Ipv6LinkLocalLeakEvidence``-shaped dict on success,
    or None when scapy is unavailable, the iface has no link-local addr,
    or no fe80:: response is seen within *timeout* seconds.
    """
    try:
        from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
        from scapy.sendrecv import sr1
    except ImportError:
        _log.debug("scapy not available — ipv6_leak active probe skipped")
        return None

    from decnet.network import list_v6_addrs
    v6_addrs = list_v6_addrs(iface)
    link_local_src = next(
        (addr for addr, scope in v6_addrs if scope == "link"), None
    )
    if link_local_src is None:
        _log.debug("ipv6_leak: no link-local addr on %s — skip active probe", iface)
        return None

    # ICMPv6 Echo to ff02::1 (all-nodes multicast) elicits responses from
    # all on-link hosts; the first fe80:: reply is the attacker's IID.
    pkt = IPv6(src=link_local_src, dst="ff02::1") / ICMPv6EchoRequest()

    try:
        resp = sr1(pkt, iface=iface, timeout=timeout, verbose=0)
    except Exception as exc:
        _log.debug("ipv6_leak: sr1 failed on %s: %s", iface, exc)
        return None

    if resp is None:
        return None

    try:
        src_addr: str = resp[IPv6].src
    except Exception:
        return None

    if not _is_link_local(src_addr):
        return None

    iid_kind, mac_oui = _ipv6_iid_classify(src_addr)
    return {
        "addr": src_addr,
        "mac_oui": mac_oui,
        "iid_kind": iid_kind,
        "vector": "active_echo",
        "on_iface": iface,
        "attacker_v4": attacker_v4,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
