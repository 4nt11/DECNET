# SPDX-License-Identifier: AGPL-3.0-or-later
"""
IP-to-ASN enrichment — maps attacker IPs to BGP-announced AS numbers and
org names for attacker intelligence.

Public surface mirrors :mod:`decnet.geoip` so callers can compose them:

* :func:`get_lookup` — returns the singleton :class:`AsnLookup`.
* :func:`enrich_ip` — takes an IP string, returns
  ``(asn_int, asn_name, bgp_prefix, provider_name)`` or ``(None, None, None, None)``.

Provider selection goes through :func:`~decnet.asn.factory.get_provider`
(env ``DECNET_ASN_PROVIDER``, default ``iptoasn``). Direct imports of
concrete providers are forbidden — mirrors the ``get_bus`` /
``get_repository`` rule.
"""
from __future__ import annotations

import os
import time
from typing import Optional, Tuple

from decnet.asn.factory import get_provider
from decnet.asn.lookup import AsnLookup
from decnet.asn.paths import ASN_ROOT

# 24 h — iptoasn refreshes daily.
REFRESH_INTERVAL_S = 86_400

_lookup: Optional[AsnLookup] = None
_provider_name: Optional[str] = None


def get_lookup(*, force_refresh: bool = False) -> AsnLookup:
    """Return the cached :class:`AsnLookup`, building it on first use.

    If the provider's data files are missing or older than
    ``REFRESH_INTERVAL_S`` seconds, refresh before building. Pass
    ``force_refresh=True`` to bypass the age check (used by a future
    ``decnet asn refresh`` CLI command).
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


def enrich_ip(ip: str) -> Tuple[Optional[int], Optional[str], Optional[str], Optional[str]]:
    """Return ``(asn, as_name, bgp_prefix, provider_name)`` or ``(None, None, None, None)``.

    Never raises — any lookup failure collapses to all-None so the
    caller (profiler) can upsert the attacker row regardless.

    ``DECNET_ASN_ENABLED=false`` short-circuits the whole path, useful
    for tests / agent hosts / ops wanting to disable enrichment without
    touching provider config.
    """
    if os.environ.get("DECNET_ASN_ENABLED", "true").lower() == "false":
        return (None, None, None, None)
    try:
        lookup = get_lookup()
        info = lookup.asn(ip)
        if info is None:
            return (None, None, None, None)
        return (info.asn, info.name or None, info.prefix, _provider_name or "unknown")
    except Exception:
        return (None, None, None, None)


def _files_stale(provider) -> bool:
    """True when the provider has no fresh data on disk.

    Same semantics as :func:`decnet.geoip._files_stale`: a partial
    cache still produces correct answers for the ranges it covers.
    """
    paths = provider.data_paths()
    if not paths:
        return True
    now = time.time()
    for p in paths:
        if p.exists() and now - p.stat().st_mtime <= REFRESH_INTERVAL_S:
            return False
    return True


__all__ = ["get_lookup", "enrich_ip", "ASN_ROOT", "REFRESH_INTERVAL_S"]
