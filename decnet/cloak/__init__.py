# SPDX-License-Identifier: AGPL-3.0-or-later
"""
DECNET cloak — egress TCP/IP fingerprint masquerading for deckies.

sysctls (decnet/os_fingerprint.py) own GLOBAL packet fields. The cloak owns the
SYN-ACK *shape* and stack *behaviours* sysctl can't reach, so a decky reads as
its claimed nmap_os under active fingerprinting (nmap -O):

  - mangler   : NFQUEUE rewrite of egress SYN-ACK (window, TCP option order,
                IP-ID generation) to match the MangleProfile for the slug.
  - responder : raw-socket synthesis of replies to probes the Linux kernel
                drops but the target OS answers (nmap T2/T3).

Both run INSIDE the decky's network namespace (CAP_NET_ADMIN), launched by the
base container — never a sidecar (that would double container count per decky).
Driven by os_fingerprint.get_os_mangle(nmap_os); a slug with no profile is a
no-op (the real Linux stack already approximates it).
"""
from __future__ import annotations

from decnet.cloak.mangler import build_synack_options, next_ipid
from decnet.cloak.responder import ProbeKind, build_reply_fields, classify_probe

__all__ = [
    "build_synack_options",
    "next_ipid",
    "classify_probe",
    "build_reply_fields",
    "ProbeKind",
]
