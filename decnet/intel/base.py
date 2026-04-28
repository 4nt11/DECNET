"""Threat-intel provider protocol.

Each concrete provider (:mod:`decnet.intel.greynoise`,
:mod:`decnet.intel.abuseipdb`, :mod:`decnet.intel.feodo`,
:mod:`decnet.intel.threatfox`) implements this. Callers must obtain
providers via :func:`decnet.intel.factory.get_intel_providers` — never
instantiate a concrete provider class directly.

Unlike :mod:`decnet.geoip` (which returns a single ``Provider``), the
intel subsystem returns a **list** of providers — enrichment fans out
across all of them per IP, and partial successes are stored row-wise.
"""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class IntelResult:
    """Per-provider enrichment outcome.

    The worker maps these into the per-provider columns on
    ``attacker_intel`` (e.g. ``greynoise_classification`` /
    ``greynoise_raw`` / ``greynoise_queried_at``).

    ``column_updates`` carries the dialect-portable column→value map the
    repository ``upsert_attacker_intel`` will apply. ``raw`` is the
    serialized provider response (already JSON-encoded by the provider so
    the worker doesn't need to know the wire shape).
    """

    provider: str
    """Short tag — matches the column prefix in ``attacker_intel``
    (``greynoise``, ``abuseipdb``, ``feodo``, ``threatfox``)."""

    column_updates: dict[str, Any] = field(default_factory=dict)
    """Columns to write on the ``attacker_intel`` row."""

    verdict: Optional[str] = None
    """Provider-local verdict label, e.g. ``"malicious"`` / ``"benign"``.
    Used by the worker to compute ``aggregate_verdict``. ``None`` =
    "no opinion" (e.g. IP not present in a blocklist)."""

    error: Optional[str] = None
    """Populated when the provider call failed. The worker logs it and
    leaves the row unchanged for this provider so a partial-success
    enrichment doesn't clobber a previous good answer."""


class IntelProvider(ABC):
    """Abstract threat-intel provider."""

    #: Short tag — matches ``IntelResult.provider`` and the column prefix
    #: on ``attacker_intel``.
    name: str

    #: Per-provider in-flight cap. Free tiers are surprisingly tight
    #: (GreyNoise community ~50/min); 4 is a safe default but providers
    #: can override.
    concurrency: int = 4

    #: Minimum seconds between dispatches. Token-bucket-lite — see
    #: :class:`decnet.intel.worker.RateLimitedDispatcher`.
    min_dispatch_interval_s: float = 0.0

    def __init__(self) -> None:
        self._semaphore = asyncio.Semaphore(self.concurrency)

    @abstractmethod
    async def lookup(self, ip: str) -> IntelResult:
        """Query the provider for ``ip`` and return the result.

        MUST NOT raise — capture errors in ``IntelResult.error`` so a
        single provider's outage doesn't break the worker pass for an
        entire IP. Implementations should also respect
        ``self._semaphore`` to bound in-flight calls.
        """
