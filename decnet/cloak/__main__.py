# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Cloak entrypoint — run inside the decky base container (CAP_NET_ADMIN).

    python -m decnet.cloak

Config via env (set by the composer when nmap_os has a mangle profile):
    DECNET_NMAP_OS    nmap_os slug (e.g. "windows", "windows_server")
    DECNET_OPEN_PORTS comma-separated TCP ports the decky serves (for T2/T3)
    DECKY_IP          this decky's IP (BPF scope for the responder)

Starts the mangler and responder, each in its own thread. A slug with no mangle
profile exits 0 immediately — harmless to launch unconditionally.
"""
from __future__ import annotations

import os
import threading

from decnet.cloak import mangler, responder
from decnet.logging import get_logger
from decnet.os_fingerprint import get_os_mangle

log = get_logger("cloak")


def _open_ports() -> frozenset[int]:
    raw = os.environ.get("DECNET_OPEN_PORTS", "")
    return frozenset(int(p) for p in raw.split(",") if p.strip().isdigit())


def main() -> int:
    nmap_os = os.environ.get("DECNET_NMAP_OS", "linux")
    if get_os_mangle(nmap_os) is None:
        log.info("cloak: no mangle profile for %r — exiting", nmap_os)
        return 0

    # Responder runs in a daemon thread; the mangler runs in the MAIN thread so
    # its SIGTERM/SIGINT iptables-teardown handlers can be installed (signal only
    # works in the main thread).
    threading.Thread(
        target=responder.run, args=(nmap_os, _open_ports()),
        name="cloak-responder", daemon=True,
    ).start()
    log.info("cloak: started for nmap_os=%r", nmap_os)
    mangler.run(nmap_os)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
