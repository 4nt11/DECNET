# SPDX-License-Identifier: AGPL-3.0-or-later
"""
GeoIP enrichment — maps attacker IPs to country codes for attacker intelligence.

Public surface:

* :func:`get_lookup` — returns the singleton :class:`~decnet.geoip.lookup.Lookup`.
  Builds / loads the index on first call. Refreshes the underlying data files
  if they're missing or older than :data:`REFRESH_INTERVAL_S`.
* :func:`enrich_ip` — convenience wrapper used by the profiler: takes an IP
  string, returns ``(country_code, provider_name)`` or ``(None, None)``.

Provider selection goes through :func:`~decnet.geoip.factory.get_provider`
(env ``DECNET_GEOIP_PROVIDER``, default ``rir``). Direct imports of concrete
providers are forbidden — mirrors the ``get_bus`` / ``get_repository`` rule.
"""
from __future__ import annotations

import os
import time
from typing import Optional, Tuple

from decnet.geoip.factory import get_provider
from decnet.geoip.lookup import Lookup
from decnet.geoip.paths import GEOIP_ROOT

# 24 h — delegated-stats files are refreshed daily by the RIRs.
REFRESH_INTERVAL_S = 86_400

_lookup: Optional[Lookup] = None
_provider_name: Optional[str] = None


def get_lookup(*, force_refresh: bool = False) -> Lookup:
    """Return the cached :class:`Lookup`, building it on first use.

    If the provider's data files are missing or older than
    ``REFRESH_INTERVAL_S`` seconds, refresh before building. Pass
    ``force_refresh=True`` to bypass the age check (used by
    ``decnet geoip refresh``).
    """
    global _lookup, _provider_name
    provider = get_provider()
    _provider_name = provider.name

    if force_refresh or _files_stale(provider):
        provider.refresh()
        _lookup = None  # rebuild on next access

    if _lookup is None:
        _lookup = provider.build_lookup()
    return _lookup


def enrich_ip(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(country_code, provider_name)`` or ``(None, None)``.

    Never raises — any lookup failure collapses to ``(None, None)`` so the
    caller (profiler) can upsert the attacker row regardless.

    ``DECNET_GEOIP_ENABLED=false`` short-circuits the whole path, useful
    for tests / agent hosts / ops wanting to disable enrichment without
    touching provider config.
    """
    if os.environ.get("DECNET_GEOIP_ENABLED", "true").lower() == "false":
        return (None, None)
    try:
        lookup = get_lookup()
        cc = lookup.country(ip)
        if cc is None:
            return (None, None)
        return (cc, _provider_name or "unknown")
    except Exception:
        return (None, None)


def _files_stale(provider) -> bool:
    """True when the provider has no fresh data on disk.

    "Fresh" = at least one data file exists whose mtime is within the
    refresh window. We don't demand every RIR file be present: a
    partial cache still produces correct answers for the ranges it
    covers, and demanding all-or-nothing would trigger a network
    refresh every time one RIR endpoint was transiently unreachable.
    """
    paths = provider.data_paths()
    if not paths:
        return True
    now = time.time()
    for p in paths:
        if p.exists() and now - p.stat().st_mtime <= REFRESH_INTERVAL_S:
            return False
    return True


__all__ = ["get_lookup", "enrich_ip", "GEOIP_ROOT", "REFRESH_INTERVAL_S"]
