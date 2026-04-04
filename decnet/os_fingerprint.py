"""
OS TCP/IP fingerprint profiles for DECNET deckies.

Maps an nmap OS family slug to a dict of Linux kernel sysctls that, when applied
to a container's network namespace, make its TCP/IP stack behaviour resemble the
claimed OS as closely as possible within the Linux kernel's constraints.

Primary discriminator leveraged by nmap: net.ipv4.ip_default_ttl (TTL)
  Linux              → 64
  Windows            → 128
  BSD (FreeBSD/macOS)→ 64  (different TCP options, but same TTL as Linux)
  Embedded / network → 255

Secondary tuning (TCP behaviour):
  net.ipv4.tcp_syn_retries  – SYN retransmits before giving up

Note: net.core.rmem_default is a global (non-namespaced) sysctl and cannot be
set per-container without --privileged; it is intentionally excluded.
"""

from __future__ import annotations

OS_SYSCTLS: dict[str, dict[str, str]] = {
    "linux": {
        "net.ipv4.ip_default_ttl": "64",
        "net.ipv4.tcp_syn_retries": "6",
    },
    "windows": {
        "net.ipv4.ip_default_ttl": "128",
        "net.ipv4.tcp_syn_retries": "2",
    },
    "bsd": {
        "net.ipv4.ip_default_ttl": "64",
        "net.ipv4.tcp_syn_retries": "6",
    },
    "embedded": {
        "net.ipv4.ip_default_ttl": "255",
        "net.ipv4.tcp_syn_retries": "3",
    },
    "cisco": {
        "net.ipv4.ip_default_ttl": "255",
        "net.ipv4.tcp_syn_retries": "2",
    },
}

_DEFAULT_OS = "linux"


def get_os_sysctls(nmap_os: str) -> dict[str, str]:
    """Return the sysctl dict for *nmap_os*.  Falls back to Linux on unknown slugs."""
    return dict(OS_SYSCTLS.get(nmap_os, OS_SYSCTLS[_DEFAULT_OS]))


def all_os_families() -> list[str]:
    """Return all registered nmap OS family slugs."""
    return list(OS_SYSCTLS.keys())
