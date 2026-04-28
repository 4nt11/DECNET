"""Bus wiring for the profiler worker (DEBT-031, worker 4).

The profiler publishes ``attacker.scored`` once per profile upsert.
Payload is a compact summary of the record the profiler just wrote to
the DB — enough for the MazeNET attacker pool to redraw without another
round-trip.

Like every other bus-wired worker, ``DECNET_BUS_ENABLED=false`` must
leave the profiler fully functional (DB-only, no publish attempts).
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.bus.publish import make_thread_safe_publisher
from decnet.correlation.engine import CorrelationEngine
from decnet.logging.syslog_formatter import SEVERITY_INFO, format_rfc5424
from decnet.profiler.worker import _WorkerState, _update_profiles


_TS = "2026-04-21T10:00:00+00:00"
_DT = datetime.fromisoformat(_TS)


def _line(ip: str = "1.2.3.4", decky: str = "decky-01") -> str:
    return format_rfc5424(
        service="ssh",
        hostname=decky,
        event_type="connection",
        severity=SEVERITY_INFO,
        timestamp=_DT,
        src_ip=ip,
    )


def _stub_repo() -> MagicMock:
    repo = MagicMock()
    repo.get_bounties_for_ips = AsyncMock(return_value={})
    repo.upsert_attacker = AsyncMock(return_value="mock-uuid")
    repo.upsert_attacker_behavior = AsyncMock()
    return repo


@pytest_asyncio.fixture
async def bus() -> FakeBus:
    b = FakeBus()
    await b.connect()
    yield b
    await b.close()


# ─── publish hook fires per upsert ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_update_profiles_publishes_scored_per_ip() -> None:
    captured: list[tuple[str, dict]] = []
    engine = CorrelationEngine()
    engine.ingest(_line(ip="1.1.1.1", decky="decky-01"))
    engine.ingest(_line(ip="2.2.2.2", decky="decky-02"))

    state = _WorkerState(
        engine=engine,
        publish_attacker=lambda event_type, payload: captured.append((event_type, payload)),
    )

    await _update_profiles(_stub_repo(), state, {"1.1.1.1", "2.2.2.2"})

    assert len(captured) == 2
    for event_type, payload in captured:
        assert event_type == "scored"
        assert payload["attacker_ip"] in {"1.1.1.1", "2.2.2.2"}
        assert payload["event_count"] == 1
        assert payload["decky_count"] == 1
        assert payload["is_traversal"] is False


@pytest.mark.asyncio
async def test_update_profiles_runs_without_publish_hook() -> None:
    # Pre-bus behavior.  No crash, upsert still happens.
    engine = CorrelationEngine()
    engine.ingest(_line(ip="3.3.3.3"))

    state = _WorkerState(engine=engine, publish_attacker=None)
    repo = _stub_repo()

    await _update_profiles(repo, state, {"3.3.3.3"})
    repo.upsert_attacker.assert_awaited_once()


@pytest.mark.asyncio
async def test_update_profiles_swallows_publish_failures() -> None:
    engine = CorrelationEngine()
    engine.ingest(_line(ip="4.4.4.4"))

    def _boom(_event_type, _payload):
        raise RuntimeError("transport exploded")

    state = _WorkerState(engine=engine, publish_attacker=_boom)
    repo = _stub_repo()

    # Must not raise; upsert still lands.
    await _update_profiles(repo, state, {"4.4.4.4"})
    repo.upsert_attacker.assert_awaited_once()


# ─── End-to-end through the bus ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_profiler_publishes_on_attacker_scored_topic(bus: FakeBus) -> None:
    loop = asyncio.get_running_loop()
    raw = make_thread_safe_publisher(bus, loop)

    def publish(event_type: str, payload: dict) -> None:
        raw(_topics.attacker(event_type), payload, event_type)

    engine = CorrelationEngine()
    engine.ingest(_line(ip="8.8.8.8", decky="decky-01"))
    state = _WorkerState(engine=engine, publish_attacker=publish)

    sub = bus.subscribe("attacker.scored")
    async with sub:
        await _update_profiles(_stub_repo(), state, {"8.8.8.8"})
        event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)

    assert event.topic == "attacker.scored"
    assert event.type == "scored"
    assert event.payload["attacker_ip"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_profiler_degrades_cleanly_when_bus_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from decnet.bus.factory import get_bus

    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")
    b = get_bus(client_name="profiler")
    await b.connect()
    await b.publish("attacker.scored", {"attacker_ip": "1.2.3.4"}, event_type="scored")
    await b.close()
