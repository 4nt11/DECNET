"""Bus wiring for the attacker prober (DEBT-031, worker 2).

The prober fingerprints observed attackers (JARM / HASSH / TCPfp) in a
``to_thread`` worker.  On each successful probe it publishes an
``attacker.fingerprinted`` event under the shared attacker root; the
probe family (jarm/hassh/tcpfp) goes in ``event.type`` so a single
subscription to ``attacker.fingerprinted`` covers all three.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
import pytest_asyncio

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.bus.publish import make_thread_safe_publisher
from decnet.prober.worker import _jarm_phase, _hassh_phase, _tcpfp_phase


@pytest_asyncio.fixture
async def bus() -> FakeBus:
    b = FakeBus()
    await b.connect()
    yield b
    await b.close()


# ─── Phase-level publish hooks ───────────────────────────────────────────────

def test_jarm_phase_invokes_publish_fn_on_success(monkeypatch, tmp_path: Path) -> None:
    captured: list[tuple[str, dict]] = []
    # Stub jarm_hash so the test doesn't touch the network.
    from decnet.prober import worker as worker_mod
    monkeypatch.setattr(worker_mod, "jarm_hash", lambda ip, port, timeout: "aabbcc")

    _jarm_phase(
        ip="203.0.113.9",
        ip_probed={},
        ports=[443],
        log_path=tmp_path / "p.log",
        json_path=tmp_path / "p.json",
        timeout=1.0,
        publish_fn=lambda event_type, payload: captured.append((event_type, payload)),
    )

    assert captured == [
        ("jarm", {"attacker_ip": "203.0.113.9", "port": 443, "jarm_hash": "aabbcc"}),
    ]


def test_jarm_phase_skips_empty_hash(monkeypatch, tmp_path: Path) -> None:
    # JARM's empty-hash sentinel means "target didn't negotiate TLS" — not
    # an observation worth publishing.
    captured: list[tuple[str, dict]] = []
    from decnet.prober import worker as worker_mod
    from decnet.prober.jarm import JARM_EMPTY_HASH
    monkeypatch.setattr(worker_mod, "jarm_hash", lambda ip, port, timeout: JARM_EMPTY_HASH)

    _jarm_phase(
        ip="1.2.3.4", ip_probed={}, ports=[443],
        log_path=tmp_path / "p.log", json_path=tmp_path / "p.json", timeout=1.0,
        publish_fn=lambda event_type, payload: captured.append((event_type, payload)),
    )
    assert captured == []


def test_hassh_phase_invokes_publish_fn_on_success(monkeypatch, tmp_path: Path) -> None:
    captured: list[tuple[str, dict]] = []
    from decnet.prober import worker as worker_mod
    monkeypatch.setattr(
        worker_mod, "hassh_server",
        lambda ip, port, timeout: {
            "hassh_server": "deadbeef",
            "banner": "SSH-2.0-OpenSSH_9.0",
            "kex_algorithms": "x",
            "encryption_s2c": "y",
            "mac_s2c": "z",
            "compression_s2c": "none",
        },
    )

    _hassh_phase(
        ip="1.2.3.4", ip_probed={}, ports=[22],
        log_path=tmp_path / "p.log", json_path=tmp_path / "p.json", timeout=1.0,
        publish_fn=lambda event_type, payload: captured.append((event_type, payload)),
    )

    assert captured == [
        ("hassh", {
            "attacker_ip": "1.2.3.4",
            "port": 22,
            "hassh_server": "deadbeef",
            "ssh_banner": "SSH-2.0-OpenSSH_9.0",
        }),
    ]


def test_tcpfp_phase_invokes_publish_fn_on_success(monkeypatch, tmp_path: Path) -> None:
    captured: list[tuple[str, dict]] = []
    from decnet.prober import worker as worker_mod
    monkeypatch.setattr(
        worker_mod, "tcp_fingerprint",
        lambda ip, port, timeout: {
            "tcpfp_hash": "cafef00d",
            "tcpfp_raw": "raw",
            "ttl": 64,
            "window_size": 29200,
            "df_bit": True,
            "mss": 1460,
            "window_scale": 7,
            "sack_ok": True,
            "timestamp": True,
            "options_order": "mss,sack,ts,nop,wscale",
            "tos": 0,
            "dscp": 0,
            "ecn": 0,
            "server_isn": 0,
        },
    )

    _tcpfp_phase(
        ip="1.2.3.4", ip_probed={}, ports=[80],
        log_path=tmp_path / "p.log", json_path=tmp_path / "p.json", timeout=1.0,
        publish_fn=lambda event_type, payload: captured.append((event_type, payload)),
    )
    assert captured == [
        ("tcpfp", {
            "attacker_ip": "1.2.3.4", "port": 80,
            "tcpfp_hash": "cafef00d", "ttl": 64, "mss": 1460,
        }),
    ]


def test_phases_run_unchanged_without_publish_fn(monkeypatch, tmp_path: Path) -> None:
    # Pre-bus behavior must stay intact when publish_fn is None.  The
    # phase still writes its log file and marks the port done — it just
    # doesn't publish.
    from decnet.prober import worker as worker_mod
    monkeypatch.setattr(worker_mod, "jarm_hash", lambda ip, port, timeout: "aabbcc")

    ip_probed: dict[str, set[int]] = {}
    _jarm_phase(
        ip="1.2.3.4", ip_probed=ip_probed, ports=[443],
        log_path=tmp_path / "p.log", json_path=tmp_path / "p.json", timeout=1.0,
        publish_fn=None,
    )
    assert 443 in ip_probed["jarm"]


# ─── End-to-end through the bus ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_prober_publishes_on_attacker_fingerprinted_topic(bus: FakeBus) -> None:
    loop = asyncio.get_running_loop()
    raw = make_thread_safe_publisher(bus, loop)

    def publish(event_type: str, payload: dict) -> None:
        raw(_topics.attacker(_topics.ATTACKER_FINGERPRINTED), payload, event_type)

    sub = bus.subscribe("attacker.fingerprinted")
    async with sub:
        publish("jarm", {"attacker_ip": "1.2.3.4", "port": 443, "jarm_hash": "h"})
        event = await asyncio.wait_for(sub.__anext__(), timeout=2.0)

    assert event.topic == "attacker.fingerprinted"
    assert event.type == "jarm"
    assert event.payload == {"attacker_ip": "1.2.3.4", "port": 443, "jarm_hash": "h"}


@pytest.mark.asyncio
async def test_prober_degrades_cleanly_when_bus_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    # DECNET_BUS_ENABLED=false returns NullBus; connect() + publish() must
    # be no-op and never raise.
    from decnet.bus.factory import get_bus

    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")
    b = get_bus(client_name="prober")
    await b.connect()
    await b.publish("attacker.fingerprinted", {"x": 1}, event_type="jarm")
    await b.close()
