"""
OS TCP/IP fingerprint profiles for DECNET deckies.

Maps an nmap OS family slug to a dict of Linux kernel sysctls that, when applied
to a container's network namespace, make its TCP/IP stack behaviour resemble the
claimed OS as closely as possible within the Linux kernel's constraints.

All sysctls listed here are network-namespace-scoped and safe to set per-container
without --privileged (beyond the NET_ADMIN capability already granted).

Primary discriminator leveraged by nmap: net.ipv4.ip_default_ttl (TTL)
  Linux              → 64
  Windows            → 128
  BSD (FreeBSD/macOS)→ 64  (different TCP options, but same TTL as Linux)
  Embedded / network → 255

Secondary discriminators (nmap OPS / WIN / ECN / T2–T6 probe groups):
  net.ipv4.tcp_syn_retries    – SYN retransmits before giving up
  net.ipv4.tcp_timestamps     – TCP timestamp option (OPS probes); Windows = off
  net.ipv4.tcp_window_scaling – Window scale option; embedded/Cisco typically off
  net.ipv4.tcp_sack           – Selective ACK option; absent on most embedded stacks
  net.ipv4.tcp_ecn            – ECN negotiation; Linux offers (2), Windows off (0)
  net.ipv4.ip_no_pmtu_disc    – DF bit in ICMP replies (IE probes); embedded on
  net.ipv4.tcp_fin_timeout    – FIN_WAIT_2 seconds (T2–T6 timing); Windows shorter

ICMP tuning (nmap IE / U1 probe groups):
  net.ipv4.icmp_ratelimit     – Min ms between ICMP error replies; Windows = 0 (none)
  net.ipv4.icmp_ratemask      – Bitmask of ICMP types subject to rate limiting

Note: net.core.rmem_default is a global (non-namespaced) sysctl and cannot be
set per-container without --privileged; TCP window size is already correct for
Windows (64240) from the kernel's default tcp_rmem settings.
"""

from __future__ import annotations

OS_SYSCTLS: dict[str, dict[str, str]] = {
    "linux": {
        "net.ipv4.ip_default_ttl": "64",
        "net.ipv4.tcp_syn_retries": "6",
        "net.ipv4.tcp_timestamps": "1",
        "net.ipv4.tcp_window_scaling": "1",
        "net.ipv4.tcp_sack": "1",
        "net.ipv4.tcp_ecn": "2",
        "net.ipv4.ip_no_pmtu_disc": "0",
        "net.ipv4.tcp_fin_timeout": "60",
        "net.ipv4.icmp_ratelimit": "1000",
        "net.ipv4.icmp_ratemask": "6168",
    },
    "windows": {
        "net.ipv4.ip_default_ttl": "128",
        "net.ipv4.tcp_syn_retries": "2",
        "net.ipv4.tcp_timestamps": "0",
        "net.ipv4.tcp_window_scaling": "1",
        "net.ipv4.tcp_sack": "1",
        "net.ipv4.tcp_ecn": "0",
        "net.ipv4.ip_no_pmtu_disc": "0",
        "net.ipv4.tcp_fin_timeout": "30",
        "net.ipv4.icmp_ratelimit": "0",
        "net.ipv4.icmp_ratemask": "0",
    },
    "bsd": {
        "net.ipv4.ip_default_ttl": "64",
        "net.ipv4.tcp_syn_retries": "6",
        "net.ipv4.tcp_timestamps": "1",
        "net.ipv4.tcp_window_scaling": "1",
        "net.ipv4.tcp_sack": "1",
        "net.ipv4.tcp_ecn": "0",
        "net.ipv4.ip_no_pmtu_disc": "0",
        "net.ipv4.tcp_fin_timeout": "60",
        "net.ipv4.icmp_ratelimit": "250",
        "net.ipv4.icmp_ratemask": "6168",
    },
    "embedded": {
        "net.ipv4.ip_default_ttl": "255",
        "net.ipv4.tcp_syn_retries": "3",
        "net.ipv4.tcp_timestamps": "0",
        "net.ipv4.tcp_window_scaling": "0",
        "net.ipv4.tcp_sack": "0",
        "net.ipv4.tcp_ecn": "0",
        "net.ipv4.ip_no_pmtu_disc": "1",
        "net.ipv4.tcp_fin_timeout": "15",
        "net.ipv4.icmp_ratelimit": "0",
        "net.ipv4.icmp_ratemask": "0",
    },
    "cisco": {
        "net.ipv4.ip_default_ttl": "255",
        "net.ipv4.tcp_syn_retries": "2",
        "net.ipv4.tcp_timestamps": "0",
        "net.ipv4.tcp_window_scaling": "0",
        "net.ipv4.tcp_sack": "0",
        "net.ipv4.tcp_ecn": "0",
        "net.ipv4.ip_no_pmtu_disc": "1",
        "net.ipv4.tcp_fin_timeout": "15",
        "net.ipv4.icmp_ratelimit": "0",
        "net.ipv4.icmp_ratemask": "0",
    },
}

_DEFAULT_OS = "linux"

_REQUIRED_SYSCTLS: frozenset[str] = frozenset(OS_SYSCTLS["linux"].keys())


def get_os_sysctls(nmap_os: str) -> dict[str, str]:
    """Return the sysctl dict for *nmap_os*.  Falls back to Linux on unknown slugs."""
    return dict(OS_SYSCTLS.get(nmap_os, OS_SYSCTLS[_DEFAULT_OS]))


def all_os_families() -> list[str]:
    """Return all registered nmap OS family slugs."""
    return list(OS_SYSCTLS.keys())

