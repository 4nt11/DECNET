# SPDX-License-Identifier: AGPL-3.0-or-later
"""Passive + active OS fingerprinting providers.

Consumed by the profiler's `sniffer_rollup` (and, longer-term, by a
dedicated prober pass). Each provider implements `base.Provider`: given
a dict of observed TCP/IP quirks (window, wscale, mss, options
signature, TTL, etc.), return a best-match OS label with confidence.

Layout mirrors `decnet/geoip/` and `decnet/bus/`: `base.py` defines the
protocol, `factory.py` is the only sanctioned accessor, and each
concrete source (p0f today, nmap-osdb / DECNET-observed later) lives in
its own subpackage. Don't import concrete provider classes directly —
use :func:`factory.get_provider` or :func:`factory.get_all_providers`.
"""
from decnet.prober.osfp.base import OsMatch, Provider
from decnet.prober.osfp.factory import (
    get_all_providers,
    get_provider,
    reset_cache,
)

__all__ = [
    "OsMatch",
    "Provider",
    "get_all_providers",
    "get_provider",
    "reset_cache",
]
