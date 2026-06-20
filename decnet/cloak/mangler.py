# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Egress SYN-ACK mangler — rewrites the TCP/IP option shape sysctl can't reach.

Split so the packet-shaping logic is pure and unit-testable without scapy, root,
or a live NFQUEUE:

  - build_synack_options() / next_ipid()  : pure, tested offline.
  - _rewrite()                            : mutates a scapy packet (lazy import).
  - run()                                 : the NFQUEUE loop (needs CAP_NET_ADMIN).

scapy/netfilterqueue are imported lazily inside the runtime functions, mirroring
decnet/prober/tcpfp.py, so importing this module is cheap and side-effect-free.
"""
from __future__ import annotations

import os
import signal
import subprocess  # nosec B404 — fixed-arg iptables, no shell
import sys
from typing import Any

from decnet.logging import get_logger
from decnet.os_fingerprint import MangleProfile, get_os_mangle

log = get_logger("cloak.mangler")

_QUEUE = 0
# Queue every egress packet carrying SYN (covers SYN-ACK incl. ECN/CWR variants);
# --queue-bypass means a dead handler never blackholes the decky.
_RULE = [
    "OUTPUT", "-p", "tcp", "--tcp-flags", "SYN", "SYN",
    "-j", "NFQUEUE", "--queue-num", str(_QUEUE), "--queue-bypass",
]


def next_ipid(prev: int, mode: str) -> int:
    """Next IP-ID for *mode*: 'incr' (TI=I), 'random' (TI=RD), 'keep' (unchanged).

    'keep' returns -1 as a sentinel meaning "do not touch the kernel's value".
    """
    if mode == "incr":
        return (prev + 1) & 0xFFFF
    if mode == "random":
        # Not for security — only to read as randomized to nmap (TI=RD).
        return int.from_bytes(os.urandom(2), "big") or 1
    return -1


def build_synack_options(
    orig_options: list[tuple[str, Any]], profile: MangleProfile
) -> list[tuple[str, Any]]:
    """Build the SYN-ACK TCP option list for *profile*, preserving the kernel's
    live Timestamp value (so nmap's SEQ.TS increment-rate test still passes).

    *orig_options* is a scapy-style ``[(name, value), ...]`` list.
    """
    ts = next((v for n, v in orig_options if n == "Timestamp"), None)
    out: list[tuple[str, Any]] = []
    for code in profile.option_order:
        if code == "MSS":
            out.append(("MSS", profile.mss))
        elif code == "WScale":
            out.append(("WScale", profile.wscale))
        elif code == "SAckOK":
            out.append(("SAckOK", b""))
        elif code == "NOP":
            out.append(("NOP", None))
        elif code == "TS":
            if ts is not None:          # only if sysctl kept timestamps on
                out.append(("Timestamp", ts))
    return out


def _is_synack(flags: int) -> bool:
    return bool(flags & 0x02) and bool(flags & 0x10)  # SYN & ACK


def _iptables(action: str) -> None:
    subprocess.run(["iptables", action, *_RULE], check=True)  # nosec B603 B607


def run(nmap_os: str) -> int:
    """Install the NFQUEUE rule and rewrite egress SYN-ACK for *nmap_os*."""
    profile = get_os_mangle(nmap_os)
    if profile is None:
        log.info("cloak.mangler: no profile for %r — nothing to do", nmap_os)
        return 0

    from netfilterqueue import NetfilterQueue  # type: ignore
    from scapy.all import IP, TCP  # type: ignore

    ipid = [0x0400]

    def _rewrite(pkt: Any) -> None:
        try:
            p = IP(pkt.get_payload())
            if p.haslayer(TCP) and _is_synack(int(p[TCP].flags)):
                p[TCP].window = profile.window
                p[TCP].options = build_synack_options(p[TCP].options, profile)
                nid = next_ipid(ipid[0], profile.ipid)
                if nid >= 0:
                    ipid[0] = nid
                    p[IP].id = nid
                # options length changed → dataofs MUST be recomputed, else the
                # kernel emits a malformed segment that breaks real connections.
                del p[IP].chksum, p[TCP].chksum, p[IP].len, p[TCP].dataofs
                pkt.set_payload(bytes(p))
        except Exception:  # nosec B110 — never drop a packet on a rewrite bug
            log.exception("cloak.mangler: rewrite failed; passing packet through")
        pkt.accept()

    _iptables("-A")
    nfq = NetfilterQueue()
    nfq.bind(_QUEUE, _rewrite)

    def _cleanup(*_: Any) -> None:
        try:
            _iptables("-D")
        finally:
            sys.exit(0)

    signal.signal(signal.SIGTERM, _cleanup)
    signal.signal(signal.SIGINT, _cleanup)
    log.info("cloak.mangler: rewriting SYN-ACK -> %s (window=%#x ipid=%s)",
             nmap_os, profile.window, profile.ipid)
    try:
        nfq.run()
    finally:
        _iptables("-D")
    return 0
