# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Probe-response synthesizer — answers the nmap probes the Linux kernel drops.

nmap's T2 (null-flags) and T3 (SYN+FIN+PSH+URG) to an OPEN port get no reply
from Linux (R=N), but Windows replies RST+ACK. We sniff the probe and inject the
target-OS-shaped reply ourselves; the kernel stays silent, so nothing races us.

Pure classification/reply logic is separated from the scapy sniff/send loop so it
is unit-testable without root or a live capture.
"""
from __future__ import annotations

import enum
import os
from typing import Any

from decnet.logging import get_logger
from decnet.os_fingerprint import get_os_mangle

log = get_logger("cloak.responder")

_NULL = 0x00
_T3 = 0x2B  # SYN+FIN+PSH+URG


class ProbeKind(enum.Enum):
    T2 = "T2"
    T3 = "T3"


def classify_probe(flags: int, dport: int, open_ports: frozenset[int]) -> ProbeKind | None:
    """Identify an nmap T2/T3 probe by flag combo + open destination port.

    Returns None for anything else (legit traffic, probes to closed ports, and
    T1/T4-T7 which the real stack already answers).
    """
    if dport not in open_ports:
        return None
    if flags == _NULL:
        return ProbeKind.T2
    if flags == _T3:
        return ProbeKind.T3
    return None


def build_reply_fields(probe_seq: int) -> dict[str, Any]:
    """Windows T2/T3 reply fields: seq 0, ack=probe seq, RST+ACK, window 0.

    (nmap T2/T3 for Windows: S=Z, A=S, F=AR, W=0, DF=1.)
    """
    return {"seq": 0, "ack": probe_seq, "flags": "RA", "window": 0, "df": True}


def run(nmap_os: str, open_ports: frozenset[int], decky_ip: str | None = None) -> int:
    """Sniff for T2/T3 probes to *open_ports* and inject Windows-shaped replies."""
    profile = get_os_mangle(nmap_os)
    if profile is None or not profile.respond_t2t3:
        log.info("cloak.responder: nothing to do for %r", nmap_os)
        return 0

    from scapy.all import IP, TCP, send, sniff  # type: ignore

    ip = decky_ip or os.environ.get("DECKY_IP", "")
    ipid = [0x0800]

    def _on(pkt: Any) -> None:
        if not pkt.haslayer(TCP):
            return
        kind = classify_probe(int(pkt[TCP].flags), int(pkt[TCP].dport), open_ports)
        if kind is None:
            return
        f = build_reply_fields(int(pkt[TCP].seq))
        ipid[0] = (ipid[0] + 1) & 0xFFFF
        reply = (
            IP(src=pkt[IP].dst, dst=pkt[IP].src, id=ipid[0], flags="DF", ttl=128)
            / TCP(sport=int(pkt[TCP].dport), dport=int(pkt[TCP].sport),
                  seq=f["seq"], ack=f["ack"], flags=f["flags"], window=f["window"])
        )
        send(reply, verbose=0)

    bpf = f"tcp and dst host {ip}" if ip else "tcp"
    log.info("cloak.responder: answering T2/T3 on %d ports (filter=%r)",
             len(open_ports), bpf)
    sniff(filter=bpf, prn=_on, store=0)
    return 0
