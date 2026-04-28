"""Threat-intel provider factory.

Returns the **list** of configured :class:`IntelProvider` instances —
diverges from :mod:`decnet.geoip.factory` (which returns a single
provider) because intel enrichment fans out across every enabled
provider per IP, with partial-success handling per row.

Configuration knobs (env-overridable; INI-driven defaults via
``decnet/config_ini.py``):

* ``DECNET_INTEL_ENABLED`` — master kill-switch (default ``true``).
* ``DECNET_INTEL_PROVIDERS`` — comma-separated list. Default
  ``"greynoise,abuseipdb,feodo,threatfox"``.

Per-provider keys (``DECNET_GREYNOISE_API_KEY``,
``DECNET_ABUSEIPDB_API_KEY``, ``DECNET_THREATFOX_API_KEY``) are read by
each concrete provider; the factory just instantiates and returns.
"""
from __future__ import annotations

import os
from typing import List

from decnet.intel.base import IntelProvider

_KNOWN_PROVIDERS = ("greynoise", "abuseipdb", "feodo", "threatfox")


def _enabled() -> bool:
    return os.environ.get("DECNET_INTEL_ENABLED", "true").lower() != "false"


def _provider_list() -> list[str]:
    raw = os.environ.get(
        "DECNET_INTEL_PROVIDERS", ",".join(_KNOWN_PROVIDERS),
    )
    return [p.strip().lower() for p in raw.split(",") if p.strip()]


def get_intel_providers() -> List[IntelProvider]:
    """Return the configured threat-intel providers.

    Returns ``[]`` when intel is disabled or the configured list is
    empty — the worker treats that as "stay running but never make a
    call," which is the right behavior for an operator who wants the
    table maintained but no egress.

    Unknown provider names raise :class:`ValueError` so a typo in
    ``decnet.ini`` surfaces immediately rather than silently dropping a
    provider.
    """
    if not _enabled():
        return []

    providers: List[IntelProvider] = []
    for name in _provider_list():
        if name == "greynoise":
            from decnet.intel.greynoise import GreyNoiseProvider
            providers.append(GreyNoiseProvider())
        elif name == "abuseipdb":
            from decnet.intel.abuseipdb import AbuseIPDBProvider
            providers.append(AbuseIPDBProvider())
        elif name == "feodo":
            from decnet.intel.feodo import FeodoProvider
            providers.append(FeodoProvider())
        elif name == "threatfox":
            from decnet.intel.threatfox import ThreatFoxProvider
            providers.append(ThreatFoxProvider())
        else:
            raise ValueError(
                f"Unknown intel provider: {name!r}. Known: {_KNOWN_PROVIDERS}"
            )
    return providers
