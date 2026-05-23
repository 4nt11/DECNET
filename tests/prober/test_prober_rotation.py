# SPDX-License-Identifier: AGPL-3.0-or-later
"""Integration test: _run_probe threads the rotation recorder through to probes.

The prober worker constructs the recorder closure at startup; here we
verify that _run_probe calls record_rotation with (ip, port, probe_type,
hash) for JARM / HASSH / TCPFP on a successful probe, and that omitting
record_rotation is a safe no-op.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from decnet.prober.worker import _run_probe


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _recorder():
    calls: list[tuple] = []
    return calls, lambda ip, port, ptype, h: calls.append((ip, port, ptype, h))


# ─── JARM ────────────────────────────────────────────────────────────────────

def test_jarm_phase_calls_recorder(tmp_path: Path) -> None:
    from decnet.prober.probes.jarm import JarmProbe
    rec_calls, recorder = _recorder()
    probe = JarmProbe()
    probe._ports = [443]

    with patch("decnet.prober.probes.jarm.jarm_hash", return_value="c0c" * 10 + "a" * 32):
        _run_probe(
            probe, "10.0.0.5", {},
            tmp_path / "decnet.log", tmp_path / "decnet.json",
            timeout=1.0, publish_fn=None, record_rotation=recorder,
        )

    assert rec_calls == [("10.0.0.5", 443, "jarm", "c0c" * 10 + "a" * 32)]


def test_jarm_phase_no_recorder_call_on_empty_hash(tmp_path: Path) -> None:
    from decnet.prober.probes.jarm import JarmProbe
    from decnet.prober.jarm import JARM_EMPTY_HASH
    rec_calls, recorder = _recorder()
    probe = JarmProbe()
    probe._ports = [443]

    with patch("decnet.prober.probes.jarm.jarm_hash", return_value=JARM_EMPTY_HASH):
        _run_probe(
            probe, "10.0.0.5", {},
            tmp_path / "decnet.log", tmp_path / "decnet.json",
            timeout=1.0, publish_fn=None, record_rotation=recorder,
        )

    assert rec_calls == []


# ─── HASSH ───────────────────────────────────────────────────────────────────

def test_hassh_phase_calls_recorder(tmp_path: Path) -> None:
    from decnet.prober.probes.hassh import HasshProbe
    rec_calls, recorder = _recorder()
    probe = HasshProbe()
    probe._ports = [22]

    stub = {
        "hassh_server": "deadbeef",
        "banner": "SSH-2.0-OpenSSH_9.2",
        "kex_algorithms": "x",
        "encryption_s2c": "x",
        "mac_s2c": "x",
        "compression_s2c": "x",
    }
    with patch("decnet.prober.probes.hassh.hassh_server", return_value=stub):
        _run_probe(
            probe, "10.0.0.5", {},
            tmp_path / "decnet.log", tmp_path / "decnet.json",
            timeout=1.0, publish_fn=None, record_rotation=recorder,
        )

    assert rec_calls == [("10.0.0.5", 22, "hassh", "deadbeef")]


# ─── TCPFP ───────────────────────────────────────────────────────────────────

def test_tcpfp_phase_calls_recorder(tmp_path: Path) -> None:
    from decnet.prober.probes.tcpfp import TcpfpProbe
    rec_calls, recorder = _recorder()
    probe = TcpfpProbe()
    probe._ports = [22]

    stub = {
        "tcpfp_hash": "tcpfp-hash-1",
        "tcpfp_raw": "raw",
        "ttl": 64, "window_size": 65535, "df_bit": True,
        "mss": 1460, "window_scale": 7, "sack_ok": True,
        "timestamp": True, "options_order": "MSS,SACK,TS,NOP,WS",
        "tos": 0, "dscp": 0, "ecn": 0, "server_isn": 0,
    }
    with patch("decnet.prober.probes.tcpfp.tcp_fingerprint", return_value=stub):
        _run_probe(
            probe, "10.0.0.5", {},
            tmp_path / "decnet.log", tmp_path / "decnet.json",
            timeout=1.0, publish_fn=None, record_rotation=recorder,
        )

    assert rec_calls == [("10.0.0.5", 22, "tcpfp", "tcpfp-hash-1")]


# ─── Safety ──────────────────────────────────────────────────────────────────

def test_recorder_optional_no_crash_when_none(tmp_path: Path) -> None:
    """record_rotation=None must keep pre-DEBT-032 behavior — no crash."""
    from decnet.prober.probes.jarm import JarmProbe
    probe = JarmProbe()
    probe._ports = [443]

    with patch("decnet.prober.probes.jarm.jarm_hash", return_value="c0c" * 10 + "a" * 32):
        _run_probe(
            probe, "10.0.0.5", {},
            tmp_path / "decnet.log", tmp_path / "decnet.json",
            timeout=1.0, publish_fn=None, record_rotation=None,
        )
