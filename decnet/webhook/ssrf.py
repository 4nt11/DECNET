# SPDX-License-Identifier: AGPL-3.0-or-later
"""SSRF egress guard for outbound webhook delivery.

Admin-supplied webhook URLs are attacker-influenceable (anyone able to
write a subscription row). Without a destination check the master can be
pointed at internal services — cloud metadata (169.254.169.254), the
loopback API, RFC1918 hosts — turning the egress path into an SSRF
primitive.

This module resolves the URL host to concrete IPs and rejects any that
are private / loopback / link-local / unspecified / reserved / multicast,
and rejects non-http(s) schemes. It returns the *validated* IP set so the
caller can connect to a checked address rather than re-resolving (which a
DNS-rebinding attacker could flip between the validation and the connect).

Fail closed: the guard is fully active unless the operator explicitly opts
out via ``DECNET_WEBHOOK_ALLOW_PRIVATE=true``.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = frozenset({"http", "https"})


class WebhookDestinationError(ValueError):
    """Raised when a webhook URL resolves to a forbidden destination.

    Subclasses ``ValueError`` so the CRUD layer can turn it into a 422 and
    the delivery layer can treat it as a terminal (non-retryable) failure.
    """


@dataclass(frozen=True)
class ValidatedDestination:
    """Result of a successful guard check.

    ``ip_addresses`` is the set of validated literal IPs the URL host
    resolved to. Connecting to one of these (instead of re-resolving the
    hostname) closes the DNS-rebinding window.
    """

    host: str
    port: int
    scheme: str
    ip_addresses: tuple[str, ...]


def _is_forbidden(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Block anything that is not a routable public address.

    ``is_global`` is the inverse of the union we care about, but we spell
    out the categories so the intent (and the audit mapping) is explicit
    and so we also catch reserved/multicast that ``is_private`` misses.
    """
    if (
        ip.is_private  # RFC1918 10/8, 172.16/12, 192.168/16, fc00::/7
        or ip.is_loopback  # 127/8, ::1
        or ip.is_link_local  # 169.254/16 (incl. 169.254.169.254), fe80::/10
        or ip.is_unspecified  # 0.0.0.0, ::
        or ip.is_reserved
        or ip.is_multicast
    ):
        return True
    # IPv4-mapped IPv6 (::ffff:a.b.c.d) hides a v4 address from the checks
    # above; unwrap and re-check so 127.0.0.1 can't sneak in as ::ffff:7f00:1.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return _is_forbidden(mapped)
    return False


def _resolve(host: str, port: int) -> tuple[str, ...]:
    """Resolve *host* to the set of literal IPs it points at.

    A bare IP literal short-circuits getaddrinfo. DNS failures raise
    ``WebhookDestinationError`` (fail closed — we never deliver to a host
    we couldn't resolve and check)."""
    try:
        ipaddress.ip_address(host)
        return (host,)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise WebhookDestinationError(
            f"webhook host {host!r} did not resolve: {exc}"
        ) from exc

    addrs = {str(info[4][0]) for info in infos}
    if not addrs:
        raise WebhookDestinationError(f"webhook host {host!r} resolved to nothing")
    return tuple(sorted(addrs))


def validate_webhook_url(url: str, *, allow_private: Optional[bool] = None) -> ValidatedDestination:
    """Validate *url* as a safe webhook egress destination.

    Raises ``WebhookDestinationError`` on a bad scheme, missing host, a host
    that won't resolve, or any resolved address that is private / loopback /
    link-local / unspecified / reserved / multicast.

    ``allow_private`` defaults to the ``DECNET_WEBHOOK_ALLOW_PRIVATE`` env
    flag (resolved lazily so tests can monkeypatch the env module). When
    True the IP-category checks are skipped, but scheme + resolvability are
    still enforced.
    """
    if allow_private is None:
        from decnet.env import DECNET_WEBHOOK_ALLOW_PRIVATE

        allow_private = DECNET_WEBHOOK_ALLOW_PRIVATE

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise WebhookDestinationError(
            f"webhook URL scheme {scheme!r} is not allowed (use http/https)"
        )

    host = parts.hostname
    if not host:
        raise WebhookDestinationError("webhook URL has no host")

    port = parts.port or (443 if scheme == "https" else 80)

    resolved = _resolve(host, port)

    if not allow_private:
        for addr in resolved:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError as exc:
                raise WebhookDestinationError(
                    f"webhook host {host!r} resolved to non-IP {addr!r}"
                ) from exc
            if _is_forbidden(ip):
                raise WebhookDestinationError(
                    f"webhook host {host!r} resolves to forbidden address {addr} "
                    "(private/loopback/link-local/reserved). Set "
                    "DECNET_WEBHOOK_ALLOW_PRIVATE=true to permit internal targets."
                )

    return ValidatedDestination(
        host=host, port=port, scheme=scheme, ip_addresses=resolved
    )
