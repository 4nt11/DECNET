# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression test for BUG-3: provider semaphore was declared but never acquired.

The ``IntelProvider`` ABC creates ``self._semaphore = asyncio.Semaphore(self.concurrency)``
in ``__init__``, but ``_enrich_one`` called ``p.lookup(ip)`` directly without
acquiring the semaphore first — concurrency and rate limits were silently
unenforced.

The fix wraps each ``p.lookup(ip)`` call with ``async with p._semaphore``.
"""
from __future__ import annotations

import asyncio
from typing import Optional

import pytest

from decnet.intel.base import IntelProvider, IntelResult
from decnet.intel.worker import _enrich_one


class _OrderedProvider(IntelProvider):
    """Test double that records order of entry/exit and enforces capacity == 1."""

    concurrency = 1  # semaphore with N=1 forces serialization
    min_dispatch_interval_s = 0.0

    def __init__(self, name: str, delay: float = 0.05) -> None:
        super().__init__()
        self.name = name
        self._delay = delay
        self.concurrent_high_watermark = 0
        self._in_flight = 0
        self.calls: list[str] = []

    async def lookup(self, ip: str) -> IntelResult:
        self._in_flight += 1
        self.concurrent_high_watermark = max(
            self.concurrent_high_watermark, self._in_flight
        )
        self.calls.append(ip)
        await asyncio.sleep(self._delay)
        self._in_flight -= 1
        return IntelResult(
            provider=self.name,
            verdict="benign",
            column_updates={},
        )


@pytest.mark.anyio
async def test_semaphore_serializes_concurrent_callers() -> None:
    """BUG-3 regression: N=1 semaphore must prevent >1 concurrent lookup.

    We fire two _enrich_one calls concurrently against the same provider
    (concurrency=1). With the semaphore enforced, the provider's
    concurrent_high_watermark stays at 1. Without it, both calls would
    enter lookup simultaneously and the watermark would reach 2.
    """
    provider = _OrderedProvider("test_provider", delay=0.05)

    results = await asyncio.gather(
        _enrich_one("uuid-a", "1.1.1.1", [provider], ttl_hours=24),
        _enrich_one("uuid-b", "2.2.2.2", [provider], ttl_hours=24),
    )

    assert len(results) == 2
    # Both callers should complete successfully.
    assert results[0]["attacker_uuid"] == "uuid-a"
    assert results[1]["attacker_uuid"] == "uuid-b"
    # The semaphore serialized access — never more than 1 in-flight at once.
    assert provider.concurrent_high_watermark == 1, (
        f"Semaphore not enforced: {provider.concurrent_high_watermark} concurrent "
        "calls observed, expected at most 1"
    )
    # Both IPs were looked up.
    assert set(provider.calls) == {"1.1.1.1", "2.2.2.2"}


@pytest.mark.anyio
async def test_semaphore_with_higher_concurrency_allows_parallel() -> None:
    """With concurrency=2, two callers may proceed simultaneously."""

    class _Wide(IntelProvider):
        concurrency = 2
        min_dispatch_interval_s = 0.0

        def __init__(self) -> None:
            super().__init__()
            self.name = "wide"
            self._in_flight = 0
            self.watermark = 0

        async def lookup(self, ip: str) -> IntelResult:
            self._in_flight += 1
            self.watermark = max(self.watermark, self._in_flight)
            await asyncio.sleep(0.05)
            self._in_flight -= 1
            return IntelResult(provider=self.name, verdict=None, column_updates={})

    wide = _Wide()
    await asyncio.gather(
        _enrich_one("uuid-a", "1.1.1.1", [wide], ttl_hours=24),
        _enrich_one("uuid-b", "2.2.2.2", [wide], ttl_hours=24),
    )
    # With concurrency=2 both calls are allowed in simultaneously.
    assert wide.watermark == 2
