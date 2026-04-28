"""OS-fingerprint provider factory.

Dispatch is env-driven (``DECNET_OSFP_PROVIDERS``, comma-separated),
with ``p0f-v2`` as the current default. Structure mirrors
:mod:`decnet.geoip.factory` exactly: lazy singletons, a ``reset_cache``
for tests, no dialect-specific globals past this module.

Callers have two entry points:

- :func:`get_provider` — fetch one provider by name (or the default).
  Used by anything that wants a single authoritative answer.
- :func:`get_all_providers` — fetch the full priority chain as a list.
  Used by the profiler's :func:`~decnet.profiler.fingerprint.sniffer_rollup`
  to try each provider in turn and take the highest-confidence match
  across all of them.

Reserved names ``dbip`` / ``maxmind`` don't apply here — we use
``nmap-osdb`` (pending Fyodor's grant) and ``decnet-observed`` (our
own DB of honeypot-captured signatures) as the reserved slots that
raise :class:`NotImplementedError` until their subpackages ship.
"""
from __future__ import annotations

import os
from typing import Optional

from decnet.prober.osfp.base import Provider


_DEFAULT_PROVIDERS = "p0f-v2"

# Lazy singletons, one per name, keyed by the env-selected order so
# resetting the env (via reset_cache in tests) rebuilds cleanly.
_cached: dict[str, Provider] = {}


def _configured_names() -> list[str]:
    raw = os.environ.get("DECNET_OSFP_PROVIDERS", _DEFAULT_PROVIDERS)
    return [n.strip() for n in raw.split(",") if n.strip()]


def _build(name: str) -> Provider:
    if name == "p0f-v2":
        from decnet.prober.osfp.p0f.provider import P0fV2Provider
        return P0fV2Provider()
    if name in ("nmap-osdb", "decnet-observed"):
        raise NotImplementedError(
            f"OS-fingerprint provider {name!r} is reserved but not yet wired."
        )
    raise ValueError(f"Unsupported OS-fingerprint provider: {name!r}")


def get_provider(name: Optional[str] = None) -> Provider:
    """Return a single provider — *name* if given, otherwise the first
    entry of ``DECNET_OSFP_PROVIDERS`` (default ``p0f-v2``).

    Lazily built, memoised. Callers MUST go through this or
    :func:`get_all_providers` — direct imports of the concrete
    provider class are forbidden per the provider-subpackage convention.
    """
    if name is None:
        names = _configured_names()
        name = names[0] if names else _DEFAULT_PROVIDERS
    cached = _cached.get(name)
    if cached is not None:
        return cached
    provider = _build(name)
    _cached[name] = provider
    return provider


def get_all_providers() -> list[Provider]:
    """Return every configured provider, in priority order.

    Declared order in ``DECNET_OSFP_PROVIDERS`` IS priority order. The
    consumer (``sniffer_rollup``) iterates and picks the best-scoring
    match across all of them; a later provider CAN beat an earlier one
    if its signature is more specific, so the "priority" is a tiebreaker,
    not a short-circuit.
    """
    return [get_provider(n) for n in _configured_names()]


def reset_cache() -> None:
    """Forget memoised providers — tests use this when monkeypatching
    ``DECNET_OSFP_PROVIDERS`` or ``decnet/prober/osfp/p0f/data/``."""
    _cached.clear()
