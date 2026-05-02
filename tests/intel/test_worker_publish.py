"""Intel worker publishes ``attacker.intel.enriched`` per enriched row.

Pins the producer wiring. The worker drains
``repo.get_unenriched_attackers``, calls the providers' ``lookup``,
upserts via ``repo.upsert_attacker_intel``, and publishes
``attacker.intel.enriched`` per row.
"""
from __future__ import annotations

import asyncio
import os
from typing import Any

import pytest

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.intel import worker as _iw
from decnet.intel.base import IntelProvider, IntelResult


class _FakeProvider(IntelProvider):
    name = "fake"

    async def lookup(self, ip: str) -> IntelResult:
        return IntelResult(
            provider="fake",
            column_updates={"fake_classification": "malicious"},
            verdict="malicious",
        )


class _RepoStub:
    def __init__(self, pending: list[dict[str, Any]]) -> None:
        self._pending = pending
        self._yielded = False
        self.upserts: list[dict[str, Any]] = []

    async def get_unenriched_attackers(
        self, *, limit: int = 100,
    ) -> list[dict[str, Any]]:
        if not self._yielded:
            self._yielded = True
            return list(self._pending)
        return []

    async def upsert_attacker_intel(self, row: dict[str, Any]) -> None:
        self.upserts.append(row)


@pytest.mark.asyncio
async def test_intel_worker_publishes_intel_enriched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bus = FakeBus()
    await bus.connect()
    monkeypatch.setattr(_iw, "get_bus", lambda *_a, **_kw: bus)

    captured: list[tuple[str, dict[str, Any]]] = []
    sub = bus.subscribe(_topics.attacker(_topics.ATTACKER_INTEL_ENRICHED))

    async def drain() -> None:
        try:
            async with sub:
                async for ev in sub:
                    captured.append((ev.topic, ev.payload))
        except Exception:
            pass

    drain_task = asyncio.create_task(drain())
    await asyncio.sleep(0)

    repo = _RepoStub([
        {"uuid": "att-1", "ip": "192.168.1.5"},
    ])
    shutdown = asyncio.Event()

    loop_task = asyncio.create_task(_iw.run_intel_loop(
        repo,  # type: ignore[arg-type]
        poll_interval_secs=0.05, ttl_hours=24,
        providers=[_FakeProvider()],
        shutdown=shutdown,
    ))
    await asyncio.sleep(0.2)
    shutdown.set()
    await asyncio.wait_for(loop_task, timeout=2.0)
    drain_task.cancel()
    await bus.close()

    assert len(repo.upserts) == 1
    assert len(captured) == 1
    topic, payload = captured[0]
    assert topic == _topics.attacker(_topics.ATTACKER_INTEL_ENRICHED)
    assert payload["attacker_uuid"] == "att-1"
    assert payload["attacker_ip"] == "192.168.1.5"
    assert payload["aggregate_verdict"] == "malicious"
    assert "fake" in payload["providers"]
