"""OS-fingerprint provider protocol + OsMatch result shape.

Each concrete provider (p0f v2 today; nmap-osdb / DECNET-observed DB
later) implements `Provider`. Callers go through
:func:`decnet.prober.osfp.factory.get_provider` or
:func:`decnet.prober.osfp.factory.get_all_providers` — direct imports
of a concrete class are forbidden, mirroring the convention in
``decnet/geoip`` and ``decnet/bus``.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class OsMatch:
    """The result of matching an observation against a provider's DB.

    Consumers should prefer higher ``confidence``. Providers compute
    confidence as the fraction of signature fields that matched exactly
    (vs. wildcard / modulo / "any" predicates) — a signature with every
    field constrained scoring 1.0, one with every field wildcarded
    approaching 0.0. This is explicit so the profiler can pick the
    most-specific match when multiple providers fire.
    """

    os: str
    flavor: str
    confidence: float
    provider: str
    is_userland: bool = False

    def __str__(self) -> str:
        tag = "userland" if self.is_userland else self.os
        return f"{tag} {self.flavor} ({self.confidence:.2f} via {self.provider})"


class Provider(ABC):
    """Abstract OS-fingerprint source.

    Providers consume a dict of observed TCP/IP quirks (``window``,
    ``wscale``, ``mss``, ``options_sig``, ``ttl``, ``df``,
    ``total_len``, ``quirks`` — not all fields required) and return a
    best-match :class:`OsMatch` or ``None`` when nothing matches.

    Providers MUST NOT raise on malformed or partial input — the
    upstream caller (`profiler/fingerprint.py::sniffer_rollup`) runs
    on data that may be missing any or all fields depending on the
    event mix, and a raising provider would wedge every attacker
    profile rebuild. Return ``None`` instead.
    """

    name: str

    @abstractmethod
    def match(self, obs: dict[str, Any]) -> Optional[OsMatch]:
        """Return best-match OsMatch for *obs*, or None."""
