"""Integration test: prober phase functions invoke the rotation recorder.

The prober worker constructs the recorder closure at startup; here we
verify that ``_probe_cycle`` threads a recorder through to JARM / HASSH
/ TCPFP phases and that the recorder gets the (ip, port, probe_type,
hash) tuple it expects.  The library itself is unit-tested separately.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from decnet.prober.worker import _probe_cycle


@patch("decnet.prober.worker.fetch_leaf_cert", return_value=None)
@patch("decnet.prober.worker.tcp_fingerprint", return_value=None)
@patch("decnet.prober.worker.hassh_server", return_value=None)
@patch("decnet.prober.worker.jarm_hash")
def test_jarm_phase_calls_recorder(
    mock_jarm: MagicMock,
    _mock_hassh: MagicMock,
    _mock_tcpfp: MagicMock,
    _mock_cert: MagicMock,
    tmp_path: Path,
):
    mock_jarm.return_value = "c0c" * 10 + "a" * 32
    log_path = tmp_path / "decnet.log"
    json_path = tmp_path / "decnet.json"
    rec_calls: list[tuple] = []
    recorder = lambda ip, port, ptype, h: rec_calls.append((ip, port, ptype, h))  # noqa: E731

    _probe_cycle(
        {"10.0.0.5"}, {},
        [443], [], [],
        log_path, json_path,
        timeout=1.0,
        publish_fn=None,
        record_rotation=recorder,
    )

    assert rec_calls == [("10.0.0.5", 443, "jarm", "c0c" * 10 + "a" * 32)]


@patch("decnet.prober.worker.fetch_leaf_cert", return_value=None)
@patch("decnet.prober.worker.tcp_fingerprint", return_value=None)
@patch("decnet.prober.worker.hassh_server")
@patch("decnet.prober.worker.jarm_hash", return_value="")
def test_hassh_phase_calls_recorder(
    _mock_jarm: MagicMock,
    mock_hassh: MagicMock,
    _mock_tcpfp: MagicMock,
    _mock_cert: MagicMock,
    tmp_path: Path,
):
    mock_hassh.return_value = {
        "hassh_server": "deadbeef",
        "banner": "SSH-2.0-OpenSSH_9.2",
        "kex_algorithms": "x",
        "encryption_s2c": "x",
        "mac_s2c": "x",
        "compression_s2c": "x",
    }
    log_path = tmp_path / "decnet.log"
    json_path = tmp_path / "decnet.json"
    rec_calls: list[tuple] = []
    recorder = lambda ip, port, ptype, h: rec_calls.append((ip, port, ptype, h))  # noqa: E731

    _probe_cycle(
        {"10.0.0.5"}, {},
        [], [22], [],
        log_path, json_path,
        timeout=1.0,
        publish_fn=None,
        record_rotation=recorder,
    )

    assert rec_calls == [("10.0.0.5", 22, "hassh", "deadbeef")]


@patch("decnet.prober.worker.fetch_leaf_cert", return_value=None)
@patch("decnet.prober.worker.tcp_fingerprint")
@patch("decnet.prober.worker.hassh_server", return_value=None)
@patch("decnet.prober.worker.jarm_hash", return_value="")
def test_tcpfp_phase_calls_recorder(
    _mock_jarm, _mock_hassh, mock_tcpfp, _mock_cert, tmp_path: Path,
):
    mock_tcpfp.return_value = {
        "tcpfp_hash": "tcpfp-hash-1",
        "tcpfp_raw": "raw",
        "ttl": 64,
        "window_size": 65535,
        "df_bit": True,
        "mss": 1460,
        "window_scale": 7,
        "sack_ok": True,
        "timestamp": True,
        "options_order": "MSS,SACK,TS,NOP,WS",
        "tos": 0,
        "dscp": 0,
        "ecn": 0,
        "server_isn": 0,
    }
    log_path = tmp_path / "decnet.log"
    json_path = tmp_path / "decnet.json"
    rec_calls: list[tuple] = []
    recorder = lambda ip, port, ptype, h: rec_calls.append((ip, port, ptype, h))  # noqa: E731

    _probe_cycle(
        {"10.0.0.5"}, {},
        [], [], [22],
        log_path, json_path,
        timeout=1.0,
        publish_fn=None,
        record_rotation=recorder,
    )

    assert rec_calls == [("10.0.0.5", 22, "tcpfp", "tcpfp-hash-1")]


@patch("decnet.prober.worker.fetch_leaf_cert", return_value=None)
@patch("decnet.prober.worker.tcp_fingerprint", return_value=None)
@patch("decnet.prober.worker.hassh_server", return_value=None)
@patch("decnet.prober.worker.jarm_hash")
def test_recorder_optional_no_crash_when_none(
    mock_jarm: MagicMock,
    _mock_hassh: MagicMock,
    _mock_tcpfp: MagicMock,
    _mock_cert: MagicMock,
    tmp_path: Path,
):
    """record_rotation=None must keep the prober's pre-DEBT-032 behavior."""
    mock_jarm.return_value = "c0c" * 10 + "a" * 32
    _probe_cycle(
        {"10.0.0.5"}, {},
        [443], [], [],
        tmp_path / "decnet.log", tmp_path / "decnet.json",
        timeout=1.0,
        publish_fn=None,
        record_rotation=None,
    )
    # No error, probe completes.
