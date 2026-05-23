# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bus wiring for the fleet sniffer (DEBT-031, worker 1).

The sniff loop itself lives in a dedicated thread running scapy and
cannot be exercised cleanly under pytest (see the "no scapy in
TestClient lifespan tests" constraint — same hazard applies here).
These tests instead pin the two things that actually carry the
contract:

1. ``SnifferEngine`` invokes ``publish_fn`` on traffic-summary events
   and skips intermediate parser artifacts.
2. The worker's thread-safe publisher marshals syncronous calls from
   the sniff thread back onto the asyncio loop where the bus lives,
   and routes them under the ``decky.{id}.traffic`` topic.
"""
from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.sniffer.fingerprint import SnifferEngine
from decnet.sniffer.worker import _make_decky_traffic_publisher


@pytest_asyncio.fixture
async def bus() -> FakeBus:
    b = FakeBus()
    await b.connect()
    yield b
    await b.close()


# ─── Engine-level publish hook ───────────────────────────────────────────────

def test_engine_publishes_on_traffic_summary_events() -> None:
    captured: list[tuple[str, str, dict]] = []

    engine = SnifferEngine(
        ip_to_decky={"10.0.0.5": "decky-a"},
        write_fn=lambda _line: None,
        publish_fn=lambda node, event, payload: captured.append((node, event, payload)),
    )

    engine._log(
        "decky-a", "tcp_flow_timing",
        src_ip="203.0.113.9", src_port="4444",
        dst_ip="10.0.0.5", dst_port="22",
        packets="17", bytes="2048", duration_s="5.1",
        mean_iat_ms="300", min_iat_ms="1", max_iat_ms="1200",
        retransmits="0",
    )

    assert captured == [(
        "decky-a", "tcp_flow_timing",
        {
            "src_ip": "203.0.113.9", "src_port": "4444",
            "dst_ip": "10.0.0.5", "dst_port": "22",
            "packets": "17", "bytes": "2048", "duration_s": "5.1",
            "mean_iat_ms": "300", "min_iat_ms": "1", "max_iat_ms": "1200",
            "retransmits": "0",
        },
    )]


def test_engine_skips_intermediate_parser_artifacts() -> None:
    captured: list[tuple[str, str, dict]] = []

    engine = SnifferEngine(
        ip_to_decky={"10.0.0.5": "decky-a"},
        write_fn=lambda _line: None,
        publish_fn=lambda node, event, payload: captured.append((node, event, payload)),
    )

    # tls_client_hello is parser intermediate — the completed tls_session
    # handshake is what downstream consumers actually want.
    engine._log("decky-a", "tls_client_hello", src_ip="1.2.3.4", ja3="abc", ja4="t13d0")
    engine._log("decky-a", "tls_certificate", src_ip="1.2.3.4", subject_cn="foo", issuer="bar")
    assert captured == []


def test_engine_no_publish_when_hook_absent() -> None:
    # Engine without publish_fn is the pre-bus behavior; the syslog line
    # is still written.  No crash, no exceptions, no publish attempts.
    calls: list[str] = []

    engine = SnifferEngine(
        ip_to_decky={"10.0.0.5": "decky-a"},
        write_fn=lambda line: calls.append(line),
    )
    engine._log(
        "decky-a", "tcp_flow_timing",
        src_ip="1.2.3.4", src_port="4", dst_ip="10.0.0.5", dst_port="22",
        packets="5", bytes="100", duration_s="2",
        mean_iat_ms="0", min_iat_ms="0", max_iat_ms="0", retransmits="0",
    )
    assert len(calls) == 1


def test_engine_swallows_publish_fn_failures() -> None:
    # A publish hook that blows up must never break the sniff thread.
    def _boom(_node, _event, _payload):
        raise RuntimeError("transport exploded")

    engine = SnifferEngine(
        ip_to_decky={"10.0.0.5": "decky-a"},
        write_fn=lambda _line: None,
        publish_fn=_boom,
    )

    # Must not raise.
    engine._log(
        "decky-a", "tcp_flow_timing",
        src_ip="1.2.3.4", src_port="4", dst_ip="10.0.0.5", dst_port="22",
        packets="5", bytes="100", duration_s="2",
        mean_iat_ms="0", min_iat_ms="0", max_iat_ms="0", retransmits="0",
    )


# ─── Thread-safe publisher (worker → bus) ────────────────────────────────────

@pytest.mark.asyncio
async def test_sniffer_worker_degrades_cleanly_when_bus_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    """``DECNET_BUS_ENABLED=false`` is the non-negotiable escape hatch.

    With the bus disabled, ``get_bus()`` returns a ``NullBus`` that
    connects without error, and the worker proceeds in publish-off mode
    without crashing.  We don't exercise the scapy sniff loop (hangs
    pytest teardown); we just assert the bus setup path is benign.
    """
    from decnet.bus.factory import get_bus

    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")
    bus = get_bus(client_name="sniffer")
    await bus.connect()
    # NullBus.publish is a no-op and must never raise.
    await bus.publish("decky.x.traffic", {"probe": "ok"}, event_type="tcp_flow_timing")
    await bus.close()


@pytest.mark.asyncio
async def test_thread_safe_publisher_routes_to_decky_traffic_topic(bus: FakeBus) -> None:
    loop = asyncio.get_running_loop()
    publish = _make_decky_traffic_publisher(bus, loop)

    sub = bus.subscribe(f"{_topics.DECKY}.*.{_topics.DECKY_TRAFFIC}")
    async with sub:
        # Fire from the same thread for test determinism — the
        # run_coroutine_threadsafe path works identically in-thread, and
        # asserting topic/payload shape is the point.
        publish("decky-a", "tcp_flow_timing", {"src_ip": "1.2.3.4"})
        event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)

    assert event.topic == "decky.decky-a.traffic"
    assert event.type == "tcp_flow_timing"
    assert event.payload == {"src_ip": "1.2.3.4"}
