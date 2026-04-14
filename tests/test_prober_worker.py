"""
Tests for the prober worker — target discovery from the log stream and
probe cycle behavior (JARM, HASSH, TCP/IP fingerprinting).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from decnet.prober.jarm import JARM_EMPTY_HASH
from decnet.prober.worker import (
    DEFAULT_PROBE_PORTS,
    DEFAULT_SSH_PORTS,
    DEFAULT_TCPFP_PORTS,
    _discover_attackers,
    _probe_cycle,
    _write_event,
)


# ─── _discover_attackers ─────────────────────────────────────────────────────

class TestDiscoverAttackers:

    def test_discovers_unique_ips(self, tmp_path: Path):
        json_file = tmp_path / "decnet.json"
        records = [
            {"service": "sniffer", "event_type": "tls_client_hello", "attacker_ip": "10.0.0.1", "fields": {}},
            {"service": "ssh", "event_type": "login_attempt", "attacker_ip": "10.0.0.2", "fields": {}},
            {"service": "sniffer", "event_type": "tls_client_hello", "attacker_ip": "10.0.0.1", "fields": {}},  # dup
        ]
        json_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        ips, pos = _discover_attackers(json_file, 0)
        assert ips == {"10.0.0.1", "10.0.0.2"}
        assert pos > 0

    def test_skips_prober_events(self, tmp_path: Path):
        json_file = tmp_path / "decnet.json"
        records = [
            {"service": "prober", "event_type": "jarm_fingerprint", "attacker_ip": "10.0.0.99", "fields": {}},
            {"service": "ssh", "event_type": "login_attempt", "attacker_ip": "10.0.0.1", "fields": {}},
        ]
        json_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        ips, _ = _discover_attackers(json_file, 0)
        assert "10.0.0.99" not in ips
        assert "10.0.0.1" in ips

    def test_skips_unknown_ips(self, tmp_path: Path):
        json_file = tmp_path / "decnet.json"
        records = [
            {"service": "sniffer", "event_type": "startup", "attacker_ip": "Unknown", "fields": {}},
        ]
        json_file.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        ips, _ = _discover_attackers(json_file, 0)
        assert len(ips) == 0

    def test_handles_missing_file(self, tmp_path: Path):
        json_file = tmp_path / "nonexistent.json"
        ips, pos = _discover_attackers(json_file, 0)
        assert len(ips) == 0
        assert pos == 0

    def test_resumes_from_position(self, tmp_path: Path):
        json_file = tmp_path / "decnet.json"
        line1 = json.dumps({"service": "ssh", "attacker_ip": "10.0.0.1", "fields": {}}) + "\n"
        json_file.write_text(line1)

        _, pos1 = _discover_attackers(json_file, 0)

        # Append more
        with open(json_file, "a") as f:
            f.write(json.dumps({"service": "ssh", "attacker_ip": "10.0.0.2", "fields": {}}) + "\n")

        ips, pos2 = _discover_attackers(json_file, pos1)
        assert ips == {"10.0.0.2"}  # only the new one
        assert pos2 > pos1

    def test_handles_file_rotation(self, tmp_path: Path):
        json_file = tmp_path / "decnet.json"
        # Write enough data to push position well ahead
        lines = [json.dumps({"service": "ssh", "attacker_ip": f"10.0.0.{i}", "fields": {}}) + "\n" for i in range(10)]
        json_file.write_text("".join(lines))
        _, pos = _discover_attackers(json_file, 0)
        assert pos > 0

        # Simulate rotation — new file is smaller than the old position
        json_file.write_text(json.dumps({"service": "ssh", "attacker_ip": "10.0.0.99", "fields": {}}) + "\n")
        assert json_file.stat().st_size < pos

        ips, new_pos = _discover_attackers(json_file, pos)
        assert "10.0.0.99" in ips

    def test_handles_malformed_json(self, tmp_path: Path):
        json_file = tmp_path / "decnet.json"
        json_file.write_text("not valid json\n" + json.dumps({"service": "ssh", "attacker_ip": "10.0.0.1", "fields": {}}) + "\n")

        ips, _ = _discover_attackers(json_file, 0)
        assert "10.0.0.1" in ips


# ─── _probe_cycle: JARM phase ──────────────────────────────────────────────

class TestProbeCycleJARM:

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_probes_new_ips(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                            mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = "c0c" * 10 + "a" * 32  # fake 62-char hash
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [443, 8443], [], [], log_path, json_path, timeout=1.0)

        assert mock_jarm.call_count == 2  # two ports
        assert 443 in probed["10.0.0.1"]["jarm"]
        assert 8443 in probed["10.0.0.1"]["jarm"]

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_skips_already_probed_ports(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                        mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = "c0c" * 10 + "a" * 32
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {"10.0.0.1": {"jarm": {443}}}

        _probe_cycle(targets, probed, [443, 8443], [], [], log_path, json_path, timeout=1.0)

        # Should only probe 8443 (443 already done)
        assert mock_jarm.call_count == 1
        mock_jarm.assert_called_once_with("10.0.0.1", 8443, timeout=1.0)

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_empty_hash_not_logged(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                    mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [443], [], [], log_path, json_path, timeout=1.0)

        assert 443 in probed["10.0.0.1"]["jarm"]
        if json_path.exists():
            content = json_path.read_text()
            assert "jarm_fingerprint" not in content

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_exception_marks_port_probed(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                          mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.side_effect = OSError("Connection refused")
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [443], [], [], log_path, json_path, timeout=1.0)

        assert 443 in probed["10.0.0.1"]["jarm"]

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_skips_ip_with_all_ports_done(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                           mock_tcpfp: MagicMock, tmp_path: Path):
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {
            "10.0.0.1": {"jarm": {443, 8443}, "hassh": set(), "tcpfp": set()},
        }

        _probe_cycle(targets, probed, [443, 8443], [], [], log_path, json_path, timeout=1.0)

        assert mock_jarm.call_count == 0


# ─── _probe_cycle: HASSH phase ─────────────────────────────────────────────

class TestProbeCycleHASSH:

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_probes_ssh_ports(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                               mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = {
            "hassh_server": "a" * 32,
            "banner": "SSH-2.0-OpenSSH_8.9p1",
            "kex_algorithms": "curve25519-sha256",
            "encryption_s2c": "aes256-gcm@openssh.com",
            "mac_s2c": "hmac-sha2-256-etm@openssh.com",
            "compression_s2c": "none",
        }
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [], [22, 2222], [], log_path, json_path, timeout=1.0)

        assert mock_hassh.call_count == 2
        assert 22 in probed["10.0.0.1"]["hassh"]
        assert 2222 in probed["10.0.0.1"]["hassh"]

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_hassh_writes_event(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                 mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = {
            "hassh_server": "b" * 32,
            "banner": "SSH-2.0-Paramiko_3.0",
            "kex_algorithms": "diffie-hellman-group14-sha1",
            "encryption_s2c": "aes128-cbc",
            "mac_s2c": "hmac-sha1",
            "compression_s2c": "none",
        }
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [], [22], [], log_path, json_path, timeout=1.0)

        assert json_path.exists()
        content = json_path.read_text()
        assert "hassh_fingerprint" in content
        record = json.loads(content.strip())
        assert record["fields"]["hassh_server_hash"] == "b" * 32
        assert record["fields"]["ssh_banner"] == "SSH-2.0-Paramiko_3.0"

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_hassh_none_not_logged(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                    mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None  # No SSH server
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [], [22], [], log_path, json_path, timeout=1.0)

        assert 22 in probed["10.0.0.1"]["hassh"]
        if json_path.exists():
            content = json_path.read_text()
            assert "hassh_fingerprint" not in content

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_hassh_skips_already_probed(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                         mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {"10.0.0.1": {"hassh": {22}}}

        _probe_cycle(targets, probed, [], [22, 2222], [], log_path, json_path, timeout=1.0)

        assert mock_hassh.call_count == 1  # only 2222
        mock_hassh.assert_called_once_with("10.0.0.1", 2222, timeout=1.0)

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_hassh_exception_marks_probed(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                           mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.side_effect = OSError("Connection refused")
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [], [22], [], log_path, json_path, timeout=1.0)

        assert 22 in probed["10.0.0.1"]["hassh"]


# ─── _probe_cycle: TCPFP phase ─────────────────────────────────────────────

class TestProbeCycleTCPFP:

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_probes_tcpfp_ports(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                 mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = {
            "tcpfp_hash": "d" * 32,
            "tcpfp_raw": "64:65535:1:1460:7:1:1:M,N,W,N,N,T,S,E",
            "ttl": 64, "window_size": 65535, "df_bit": 1,
            "mss": 1460, "window_scale": 7, "sack_ok": 1,
            "timestamp": 1, "options_order": "M,N,W,N,N,T,S,E",
        }
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [], [], [80, 443], log_path, json_path, timeout=1.0)

        assert mock_tcpfp.call_count == 2
        assert 80 in probed["10.0.0.1"]["tcpfp"]
        assert 443 in probed["10.0.0.1"]["tcpfp"]

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_tcpfp_writes_event_with_all_fields(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                                  mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = {
            "tcpfp_hash": "e" * 32,
            "tcpfp_raw": "128:8192:1:1460:8:1:0:M,N,W,N,N,S",
            "ttl": 128, "window_size": 8192, "df_bit": 1,
            "mss": 1460, "window_scale": 8, "sack_ok": 1,
            "timestamp": 0, "options_order": "M,N,W,N,N,S",
        }
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [], [], [443], log_path, json_path, timeout=1.0)

        content = json_path.read_text()
        assert "tcpfp_fingerprint" in content
        record = json.loads(content.strip())
        assert record["fields"]["tcpfp_hash"] == "e" * 32
        assert record["fields"]["ttl"] == "128"
        assert record["fields"]["window_size"] == "8192"
        assert record["fields"]["options_order"] == "M,N,W,N,N,S"

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_tcpfp_none_not_logged(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                    mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [], [], [443], log_path, json_path, timeout=1.0)

        assert 443 in probed["10.0.0.1"]["tcpfp"]
        if json_path.exists():
            content = json_path.read_text()
            assert "tcpfp_fingerprint" not in content


# ─── Probe type isolation ───────────────────────────────────────────────────

class TestProbeTypeIsolation:

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_jarm_does_not_mark_hassh(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                       mock_tcpfp: MagicMock, tmp_path: Path):
        """JARM probing port 2222 should not mark HASSH port 2222 as done."""
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        # Probe with JARM on 2222 and HASSH on 2222
        _probe_cycle(targets, probed, [2222], [2222], [], log_path, json_path, timeout=1.0)

        # Both should be called
        assert mock_jarm.call_count == 1
        assert mock_hassh.call_count == 1
        assert 2222 in probed["10.0.0.1"]["jarm"]
        assert 2222 in probed["10.0.0.1"]["hassh"]

    @patch("decnet.prober.worker.tcp_fingerprint")
    @patch("decnet.prober.worker.hassh_server")
    @patch("decnet.prober.worker.jarm_hash")
    def test_all_three_probes_run(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                   mock_tcpfp: MagicMock, tmp_path: Path):
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, [443], [22], [80], log_path, json_path, timeout=1.0)

        assert mock_jarm.call_count == 1
        assert mock_hassh.call_count == 1
        assert mock_tcpfp.call_count == 1


# ─── _write_event ────────────────────────────────────────────────────────────

class TestWriteEvent:

    def test_writes_rfc5424_and_json(self, tmp_path: Path):
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        _write_event(log_path, json_path, "test_event", target_ip="10.0.0.1", msg="test")

        assert log_path.exists()
        assert json_path.exists()

        log_content = log_path.read_text()
        assert "test_event" in log_content
        assert "decnet@55555" in log_content

        json_content = json_path.read_text()
        record = json.loads(json_content.strip())
        assert record["event_type"] == "test_event"
        assert record["service"] == "prober"
        assert record["fields"]["target_ip"] == "10.0.0.1"
