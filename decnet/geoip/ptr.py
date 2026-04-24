"""Reverse DNS (PTR record) lookup for attacker IPs.

Colocated with ``decnet.geoip`` because the shape matches: take an IP,
return a piece of supplementary metadata, never raise. Same operator
posture as ``enrich_ip`` — a missing PTR must never break profile
building.

The profiler calls this once per attacker IP at first sighting. Never
re-resolves — the profiler tracks already-attempted IPs in-memory
(``_WorkerState.ptr_attempted``) so a persistent NXDOMAIN doesn't burn
2 seconds of tick time on every cycle.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import socket
from typing import Optional

from decnet.logging import get_logger

log = get_logger("geoip.ptr")


_DEFAULT_TIMEOUT = 2.0


def _is_resolvable(ip: str) -> bool:
    """True iff ``ip`` is a parseable public address worth querying.

    Private / loopback / link-local / multicast / reserved addresses
    have no meaningful PTR at the public resolver level, so short-
    circuit before spending a DNS round-trip on them.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    if addr.is_loopback or addr.is_private or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    return True


def _blocking_lookup(ip: str) -> Optional[str]:
    """Synchronous PTR lookup — runs in the executor thread."""
    try:
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
        return hostname or None
    except (socket.herror, socket.gaierror, OSError):
        return None


async def resolve_ptr_record(
    ip: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
) -> Optional[str]:
    """Resolve *ip* to a PTR / rDNS hostname.

    Returns the canonical hostname on success, ``None`` on any failure
    (NXDOMAIN, timeout, malformed input, env kill-switch). Never raises
    — PTR is supplementary attacker metadata; a missing lookup must not
    break profile building.

    Honours ``DECNET_PTR_ENABLED=false`` for locked-down environments
    where egress DNS is forbidden.
    """
    if os.environ.get("DECNET_PTR_ENABLED", "true").lower() == "false":
        return None
    if not _is_resolvable(ip):
        return None

    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(None, _blocking_lookup, ip),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        log.debug("ptr: timeout resolving %s after %.1fs", ip, timeout)
        return None
    except Exception as exc:  # noqa: BLE001 — supplementary metadata
        log.debug("ptr: resolver crashed for %s: %s", ip, exc)
        return None
