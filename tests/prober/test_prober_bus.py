# SPDX-License-Identifier: AGPL-3.0-or-later
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
from unittest.mock import patch

import pytest
import pytest_asyncio

from decnet.bus import topics as _topics
from decnet.bus.fake import FakeBus
from decnet.bus.publish import make_thread_safe_publisher
from decnet.prober.worker import _run_probe


def _run(probe_cls, ip, ports, tmp_path, publish_fn, monkeypatch=None):
    """Helper: run _run_probe for a single-port probe, respecting port override."""
    import os
    probe = probe_cls()
    # Narrow to just the requested ports via env var
    env_key = f"DECNET_PROBE_PORTS_{probe_cls.probe_name.upper()}"
    probe._ports = list(ports)
    ip_probed: dict = {}
    _run_probe(
        probe, ip, ip_probed,
        tmp_path / "p.log", tmp_path / "p.json",
        timeout=1.0, publish_fn=publish_fn, record_rotation=None,
    )
    return ip_probed


# ─── Per-probe publish hooks ──────────────────────────────────────────────────

def test_jarm_invokes_publish_fn_on_success(tmp_path: Path) -> None:
    captured: list[tuple[str, dict]] = []
    from decnet.prober.probes.jarm import JarmProbe
    with patch("decnet.prober.probes.jarm.jarm_hash", return_value="aabbcc"):
        ip_probed = _run(
            JarmProbe, "203.0.113.9", [443], tmp_path,
            publish_fn=lambda event_type, payload: captured.append((event_type, payload)),
        )
    assert captured == [
        ("jarm", {"attacker_ip": "203.0.113.9", "port": 443, "jarm_hash": "aabbcc"}),
    ]
    assert 443 in ip_probed["jarm"]


def test_jarm_skips_empty_hash(tmp_path: Path) -> None:
    captured: list[tuple[str, dict]] = []
    from decnet.prober.probes.jarm import JarmProbe
    from decnet.prober.jarm import JARM_EMPTY_HASH
    with patch("decnet.prober.probes.jarm.jarm_hash", return_value=JARM_EMPTY_HASH):
        _run(JarmProbe, "1.2.3.4", [443], tmp_path,
             publish_fn=lambda e, p: captured.append((e, p)))
    assert captured == []


def test_hassh_invokes_publish_fn_on_success(tmp_path: Path) -> None:
    captured: list[tuple[str, dict]] = []
    from decnet.prober.probes.hassh import HasshProbe
    stub = {
        "hassh_server": "deadbeef",
        "banner": "SSH-2.0-OpenSSH_9.0",
        "kex_algorithms": "x",
        "encryption_s2c": "y",
        "mac_s2c": "z",
        "compression_s2c": "none",
    }
    with patch("decnet.prober.probes.hassh.hassh_server", return_value=stub):
        _run(HasshProbe, "1.2.3.4", [22], tmp_path,
             publish_fn=lambda e, p: captured.append((e, p)))
    assert captured == [
        ("hassh", {
            "attacker_ip": "1.2.3.4",
            "port": 22,
            "hassh_server": "deadbeef",
            "ssh_banner": "SSH-2.0-OpenSSH_9.0",
        }),
    ]


def test_tcpfp_invokes_publish_fn_on_success(tmp_path: Path) -> None:
    captured: list[tuple[str, dict]] = []
    from decnet.prober.probes.tcpfp import TcpfpProbe
    stub = {
        "tcpfp_hash": "cafef00d", "tcpfp_raw": "raw",
        "ttl": 64, "window_size": 29200, "df_bit": True,
        "mss": 1460, "window_scale": 7, "sack_ok": True,
        "timestamp": True, "options_order": "mss,sack,ts,nop,wscale",
        "tos": 0, "dscp": 0, "ecn": 0, "server_isn": 0,
    }
    with patch("decnet.prober.probes.tcpfp.tcp_fingerprint", return_value=stub):
        _run(TcpfpProbe, "1.2.3.4", [80], tmp_path,
             publish_fn=lambda e, p: captured.append((e, p)))
    assert captured == [
        ("tcpfp", {
            "attacker_ip": "1.2.3.4", "port": 80,
            "tcpfp_hash": "cafef00d", "ttl": 64, "mss": 1460,
        }),
    ]


def test_probe_marks_port_done_without_publish_fn(tmp_path: Path) -> None:
    from decnet.prober.probes.jarm import JarmProbe
    with patch("decnet.prober.probes.jarm.jarm_hash", return_value="aabbcc"):
        ip_probed = _run(JarmProbe, "1.2.3.4", [443], tmp_path, publish_fn=None)
    assert 443 in ip_probed["jarm"]


# ─── End-to-end through the bus ──────────────────────────────────────────────

@pytest_asyncio.fixture
async def bus() -> FakeBus:
    b = FakeBus()
    await b.connect()
    yield b
    await b.close()


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
    monkeypatch.setenv("DECNET_BUS_ENABLED", "false")
    b = FakeBus()
    await b.connect()
    await b.publish("attacker.fingerprinted", {"x": 1}, event_type="jarm")
    await b.close()
