"""Passive + active OS fingerprinting providers.

Consumed by the profiler's `sniffer_rollup` (and, longer-term, by a
dedicated prober pass). Each provider implements `base.Provider`: given a
dict of observed TCP/IP quirks (window, wscale, mss, options signature,
TTL, etc.), return a best-match OS label with confidence.

Layout mirrors `decnet/geoip/` and `decnet/bus/`: `base.py` defines the
protocol, `factory.py` is the only sanctioned accessor, and each concrete
source (p0f, eventually nmap-osdb / our own curated DB) lives in its own
subpackage. Don't import concrete provider classes directly.
"""
