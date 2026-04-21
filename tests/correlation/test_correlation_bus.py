"""Bus wiring for the correlation engine (DEBT-031, worker 3).

The correlator is not a standalone worker — ``CorrelationEngine`` is a
batch class instantiated inside the profiler worker.  DEBT-031 wires it
via an optional ``publish_fn`` constructor arg: on the first sighting of
an attacker IP, the engine emits ``("observed", payload)`` through the
hook.  The profiler worker carries the bus physically and translates
those sync hook calls into ``attacker.observed`` publishes.
"""
from __future__ import annotations

import asyncio
from datetime import datetime

import pytest
import pytest_asyncio

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.bus.publish import make_thread_safe_publisher
from decnet.correlation.engine import CorrelationEngine
from decnet.logging.syslog_formatter import SEVERITY_INFO, format_rfc5424


_TS = "2026-04-21T10:00:00+00:00"


def _line(ip: str = "1.2.3.4", decky: str = "decky-01", event_type: str = "connection") -> str:
    return format_rfc5424(
        service="http",
        hostname=decky,
        event_type=event_type,
        severity=SEVERITY_INFO,
        timestamp=datetime.fromisoformat(_TS),
        src_ip=ip,
    )


@pytest_asyncio.fixture
async def bus() -> FakeBus:
    b = FakeBus()
    await b.connect()
    yield b
    await b.close()


# ─── Engine-level publish hook ───────────────────────────────────────────────

def test_engine_publishes_once_on_first_sighting() -> None:
    captured: list[tuple[str, dict]] = []
    engine = CorrelationEngine(
        publish_fn=lambda event_type, payload: captured.append((event_type, payload)),
    )

    # Same IP three times: only the first should publish.
    engine.ingest(_line(ip="9.9.9.9"))
    engine.ingest(_line(ip="9.9.9.9", event_type="login"))
    engine.ingest(_line(ip="9.9.9.9", decky="decky-02"))

    assert len(captured) == 1
    event_type, payload = captured[0]
    assert event_type == "observed"
    assert payload["attacker_ip"] == "9.9.9.9"
    assert payload["decky"] == "decky-01"
    assert payload["service"] == "http"
    assert payload["event_type"] == "connection"
    assert payload["first_seen"].startswith("2026-04-21T10:00:00")


def test_engine_publishes_per_unique_ip() -> None:
    captured: list[tuple[str, dict]] = []
    engine = CorrelationEngine(
        publish_fn=lambda event_type, payload: captured.append((event_type, payload)),
    )

    engine.ingest(_line(ip="1.1.1.1"))
    engine.ingest(_line(ip="2.2.2.2"))
    engine.ingest(_line(ip="1.1.1.1"))  # dup, no publish
    engine.ingest(_line(ip="3.3.3.3"))

    ips = [p["attacker_ip"] for _, p in captured]
    assert ips == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


def test_engine_swallows_publish_fn_failures() -> None:
    # A publish hook that blows up must never break ingestion.
    def _boom(_event_type, _payload):
        raise RuntimeError("transport exploded")

    engine = CorrelationEngine(publish_fn=_boom)
    result = engine.ingest(_line(ip="5.5.5.5"))
    assert result is not None
    assert engine.events_indexed == 1


def test_engine_runs_unchanged_without_publish_fn() -> None:
    # Pre-bus behavior.  No hook, no publishes, same indexing result.
    engine = CorrelationEngine()
    engine.ingest(_line(ip="7.7.7.7"))
    engine.ingest(_line(ip="7.7.7.7"))
    assert engine.events_indexed == 2


def test_engine_ignores_lines_without_attacker_ip() -> None:
    captured: list[tuple[str, dict]] = []
    engine = CorrelationEngine(
        publish_fn=lambda event_type, payload: captured.append((event_type, payload)),
    )
    # Line without src_ip — parser still returns a LogEvent but attacker_ip is empty.
    line_no_ip = format_rfc5424(
        service="http",
        hostname="decky-01",
        event_type="boot",
        severity=SEVERITY_INFO,
        timestamp=datetime.fromisoformat(_TS),
    )
    engine.ingest(line_no_ip)
    assert captured == []


# ─── End-to-end through the bus ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_correlator_publishes_on_attacker_observed_topic(bus: FakeBus) -> None:
    loop = asyncio.get_running_loop()
    raw = make_thread_safe_publisher(bus, loop)

    def publish(event_type: str, payload: dict) -> None:
        raw(_topics.attacker(_topics.ATTACKER_OBSERVED), payload, event_type)

    engine = CorrelationEngine(publish_fn=publish)

    sub = bus.subscribe("attacker.observed")
    async with sub:
        engine.ingest(_line(ip="8.8.8.8"))
        event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)

    assert event.topic == "attacker.observed"
    assert event.type == "observed"
    assert event.payload["attacker_ip"] == "8.8.8.8"


@pytest.mark.asyncio
async def test_correlator_degrades_cleanly_when_bus_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # DECNET_BUS_ENABLED=false returns NullBus; connect()+publish must never raise.
    from decnet.bus.factory import get_bus

    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")
    b = get_bus(client_name="profiler")
    await b.connect()
    await b.publish("attacker.observed", {"attacker_ip": "1.2.3.4"}, event_type="observed")
    await b.close()
