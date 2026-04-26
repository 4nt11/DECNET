"""Threat-intel enrichment subsystem — out-of-band lookups for attacker IPs.

Sibling to :mod:`decnet.geoip` and :mod:`decnet.asn`, but runs as a
separate worker (``decnet enrich``) rather than inline in the profiler:
3rd-party HTTP latency and free-tier rate limits should not block the
profiler tick.

Public surface: :func:`decnet.intel.factory.get_intel_providers` and the
:class:`decnet.intel.base.IntelProvider` ABC.
"""
