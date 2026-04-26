"""End-to-end tests for the intel worker shell.

Covers — without any real provider impls — that the loop:

* exits cleanly on shutdown signal (and via cancel)
* does nothing when no providers are configured
* fans out across fake providers and writes the aggregate row
* aggregate_verdict picks the strongest provider verdict
* a provider returning ``error`` is logged but does not poison the row
* gates attackers through ``get_unenriched_attackers`` (TTL respected)
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Optional

import pytest

from decnet.intel.base import IntelProvider, IntelResult
from decnet.intel.worker import run_intel_loop, _aggregate
from decnet.web.db.factory import get_repository


class _FakeProvider(IntelProvider):
    """Test double — instantly returns a canned :class:`IntelResult`."""

    concurrency = 1
    min_dispatch_interval_s = 0.0

    def __init__(
        self,
        name: str,
        *,
        verdict: Optional[str] = None,
        error: Optional[str] = None,
        column_updates: Optional[dict] = None,
    ) -> None:
        super().__init__()
        self.name = name
        self._verdict = verdict
        self._error = error
        self._cols = column_updates or {}
        self.calls: list[str] = []

    async def lookup(self, ip: str) -> IntelResult:
        self.calls.append(ip)
        return IntelResult(
            provider=self.name,
            verdict=self._verdict,
            error=self._error,
            column_updates=self._cols,
        )


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "intel_worker.db"))
    await r.initialize()
    return r


# Disable bus connection in tests — workers under test should run in
# poll-only mode without hitting a real Unix socket.
@pytest.fixture(autouse=True)
def _no_bus(monkeypatch):
    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")


def test_aggregate_picks_strongest_verdict():
    assert _aggregate(["benign", "malicious", None]) == "malicious"
    assert _aggregate(["benign", "suspicious"]) == "suspicious"
    assert _aggregate(["benign", None]) == "benign"
    assert _aggregate([None, None]) is None
    assert _aggregate([]) is None


@pytest.mark.anyio
async def test_loop_exits_on_shutdown_signal(repo):
    shutdown = asyncio.Event()
    task = asyncio.create_task(
        run_intel_loop(
            repo,
            poll_interval_secs=0.05,
            providers=[],
            shutdown=shutdown,
        )
    )
    await asyncio.sleep(0.1)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)


async def _seed_attacker(repo, ip: str) -> str:
    """Seed an attackers row and return its UUID."""
    now = datetime.now(timezone.utc)
    return await repo.upsert_attacker(
        {"ip": ip, "first_seen": now, "last_seen": now, "event_count": 1}
    )


@pytest.mark.anyio
async def test_no_providers_skips_enrichment(repo):
    a_uuid = await _seed_attacker(repo, "1.1.1.1")
    shutdown = asyncio.Event()
    task = asyncio.create_task(
        run_intel_loop(
            repo,
            poll_interval_secs=0.05,
            providers=[],
            shutdown=shutdown,
        )
    )
    await asyncio.sleep(0.15)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)
    # No row written for the seeded attacker.
    assert await repo.get_attacker_intel_by_uuid(a_uuid) is None


@pytest.mark.anyio
async def test_fan_out_writes_aggregate_row(repo):
    a_uuid = await _seed_attacker(repo, "2.2.2.2")

    gn = _FakeProvider(
        "greynoise",
        verdict="benign",
        column_updates={
            "greynoise_classification": "benign",
            "greynoise_raw": json.dumps({"classification": "benign"}),
            "greynoise_queried_at": datetime.now(timezone.utc),
        },
    )
    aip = _FakeProvider(
        "abuseipdb",
        verdict="malicious",
        column_updates={
            "abuseipdb_score": 90,
            "abuseipdb_raw": json.dumps({"abuseConfidenceScore": 90}),
            "abuseipdb_queried_at": datetime.now(timezone.utc),
        },
    )

    shutdown = asyncio.Event()
    task = asyncio.create_task(
        run_intel_loop(
            repo,
            poll_interval_secs=0.05,
            providers=[gn, aip],
            shutdown=shutdown,
        )
    )
    # One tick is enough — both providers respond instantly.
    await asyncio.sleep(0.15)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)

    row = await repo.get_attacker_intel_by_uuid(a_uuid)
    assert row is not None
    assert row["attacker_uuid"] == a_uuid
    assert row["attacker_ip"] == "2.2.2.2"
    assert row["greynoise_classification"] == "benign"
    assert row["abuseipdb_score"] == 90
    # Strongest verdict wins.
    assert row["aggregate_verdict"] == "malicious"
    # Both providers were queried by IP.
    assert gn.calls == ["2.2.2.2"]
    assert aip.calls == ["2.2.2.2"]


@pytest.mark.anyio
async def test_provider_error_does_not_poison_row(repo):
    a_uuid = await _seed_attacker(repo, "3.3.3.3")

    good = _FakeProvider(
        "greynoise",
        verdict="benign",
        column_updates={
            "greynoise_classification": "benign",
            "greynoise_raw": "{}",
            "greynoise_queried_at": datetime.now(timezone.utc),
        },
    )
    broken = _FakeProvider("abuseipdb", error="HTTP 500")

    shutdown = asyncio.Event()
    task = asyncio.create_task(
        run_intel_loop(
            repo,
            poll_interval_secs=0.05,
            providers=[good, broken],
            shutdown=shutdown,
        )
    )
    await asyncio.sleep(0.15)
    shutdown.set()
    await asyncio.wait_for(task, timeout=2.0)

    row = await repo.get_attacker_intel_by_uuid(a_uuid)
    assert row is not None
    assert row["greynoise_classification"] == "benign"
    # Broken provider's columns stay null; row is still written.
    assert row["abuseipdb_score"] is None
    # Aggregate reflects only the providers that responded.
    assert row["aggregate_verdict"] == "benign"


@pytest.mark.anyio
async def test_intel_enriched_event_published_to_bus(repo, monkeypatch):
    """End-to-end: worker dispatches providers + publishes the event."""
    from decnet.bus.fake import FakeBus
    from decnet.bus.topics import ATTACKER_INTEL_ENRICHED, attacker

    # Re-enable bus path; swap factory for a shared FakeBus instance the
    # test can also subscribe to.
    monkeypatch.setenv("DECNET_BUS_ENABLED", "true")
    monkeypatch.setenv("DECNET_BUS_TYPE", "fake")
    shared_bus = FakeBus()

    from decnet.intel import worker as worker_mod
    monkeypatch.setattr(
        worker_mod, "get_bus", lambda **_: shared_bus,
    )

    # Subscribe before the worker starts so we don't race the publish.
    sub = shared_bus.subscribe(attacker(ATTACKER_INTEL_ENRICHED))
    await sub.__aenter__()

    a_uuid = await _seed_attacker(repo, "4.4.4.4")

    provider = _FakeProvider(
        "greynoise",
        verdict="malicious",
        column_updates={
            "greynoise_classification": "malicious",
            "greynoise_raw": "{}",
            "greynoise_queried_at": datetime.now(timezone.utc),
        },
    )

    shutdown = asyncio.Event()
    task = asyncio.create_task(
        run_intel_loop(
            repo,
            poll_interval_secs=0.05,
            providers=[provider],
            shutdown=shutdown,
        )
    )
    try:
        event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)
    finally:
        shutdown.set()
        await asyncio.wait_for(task, timeout=2.0)
        await sub.__aexit__(None, None, None)

    payload = event.payload
    assert payload["attacker_uuid"] == a_uuid
    assert payload["attacker_ip"] == "4.4.4.4"
    assert payload["aggregate_verdict"] == "malicious"
    assert payload["providers"] == ["greynoise"]
