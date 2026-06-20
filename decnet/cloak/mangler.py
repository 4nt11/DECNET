# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Egress mangler — rewrites the TCP/IP shape & behaviours sysctl can't reach.

Touches only the fingerprint-relevant egress packets:
  - SYN-ACK : window, TCP option order, IP-ID (nmap OPS/WIN/TI)
  - RST     : IP-ID + a nonzero ack on bare RSTs (nmap CI, T4/T6 A=O)
  - ICMP echo-reply : code=0 + IP-ID (nmap IE.CD, II)
A single shared IP-ID counter across all three reads as a shared sequence (SS=S).

Split so the packet-shaping logic is pure and unit-testable without scapy, root,
or a live NFQUEUE:

  - build_synack_options() / next_ipid() / _rst_needs_ack() : pure, tested offline.
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
import threading
from typing import Any

from decnet.logging import get_logger
from decnet.os_fingerprint import MangleProfile, get_os_mangle

log = get_logger("cloak.mangler")

_QUEUE = 0
# Only the fingerprint-relevant egress packets are queued (never bulk data):
#   SYN-bearing  → SYN-ACK (OPS/WIN/options/TI)
#   RST-bearing  → T4-T7 RST shape (CI IP-ID, T4/T6 ack)
#   ICMP echo-reply → IE.CD code + II IP-ID
# --queue-bypass: a dead handler never blackholes the decky.
def _nfq_rule(match: list[str]) -> list[str]:
    return ["OUTPUT", *match, "-j", "NFQUEUE", "--queue-num", str(_QUEUE), "--queue-bypass"]


_RULES = [
    _nfq_rule(["-p", "tcp", "--tcp-flags", "SYN", "SYN"]),
    _nfq_rule(["-p", "tcp", "--tcp-flags", "RST", "RST"]),
    _nfq_rule(["-p", "icmp", "--icmp-type", "echo-reply"]),
]


def _rst_needs_ack(flags: int) -> bool:
    """A bare RST (RST set, ACK clear) — the T4/T6 case. Windows fills a nonzero
    ack (nmap A=O); Linux leaves it 0 (A=Z). R+ACK RSTs (T5/T7) already match."""
    return bool(flags & 0x04) and not (flags & 0x10)


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
    for rule in _RULES:
        subprocess.run(["iptables", action, *rule], check=True)  # nosec B603 B607


def run(nmap_os: str) -> int:
    """Install the NFQUEUE rules and rewrite egress SYN-ACK / RST / ICMP for *nmap_os*."""
    profile = get_os_mangle(nmap_os)
    if profile is None:
        log.info("cloak.mangler: no profile for %r — nothing to do", nmap_os)
        return 0

    from netfilterqueue import NetfilterQueue  # type: ignore
    from scapy.all import ICMP, IP, TCP  # type: ignore

    # ONE shared IP-ID counter across SYN-ACK / RST / ICMP — keeps TCP and ICMP
    # IDs close, which is what nmap reads as a shared sequence (SS=S, Windows).
    ipid = [0x0400]

    def _bump_ipid(p: Any) -> None:
        nid = next_ipid(ipid[0], profile.ipid)
        if nid >= 0:
            ipid[0] = nid
            p[IP].id = nid

    def _rewrite(pkt: Any) -> None:
        try:
            p = IP(pkt.get_payload())
            touched = False
            tcp_synack = False
            if p.haslayer(TCP):
                f = int(p[TCP].flags)
                if _is_synack(f):
                    p[TCP].window = profile.window
                    p[TCP].options = build_synack_options(p[TCP].options, profile)
                    _bump_ipid(p)
                    touched = tcp_synack = True
                elif f & 0x04:  # RST (T4-T7)
                    _bump_ipid(p)
                    if _rst_needs_ack(f):
                        p[TCP].ack = (int(p[TCP].seq) + 1) & 0xFFFFFFFF  # A=O
                    touched = True
                if touched:
                    del p[TCP].chksum
                    if tcp_synack:  # options length changed → recompute offset
                        del p[TCP].dataofs
            elif p.haslayer(ICMP) and int(p[ICMP].type) == 0:  # echo-reply
                p[ICMP].code = 0          # IE.CD=Z (Windows); Linux echoes the code
                _bump_ipid(p)
                del p[ICMP].chksum
                touched = True
            if touched:
                del p[IP].chksum, p[IP].len
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

    # signal.signal() only works in the main thread; the `finally` below still
    # removes the rule on a normal exit, and on container stop the netns (and
    # its iptables rules) are torn down regardless.
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, _cleanup)
        signal.signal(signal.SIGINT, _cleanup)
    log.info("cloak.mangler: rewriting SYN-ACK/RST/ICMP -> %s (window=%#x ipid=%s)",
             nmap_os, profile.window, profile.ipid)
    try:
        nfq.run()
    finally:
        _iptables("-D")
    return 0
