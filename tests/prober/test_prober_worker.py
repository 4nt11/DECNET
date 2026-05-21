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
from decnet.prober.probes.hassh import HasshProbe
from decnet.prober.probes.jarm import JarmProbe
from decnet.prober.probes.tcpfp import TcpfpProbe
from decnet.prober.worker import (
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

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_probes_new_ips(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                            mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                            tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [443, 8443])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        mock_jarm.return_value = "c0c" * 10 + "a" * 32  # fake 62-char hash
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert mock_jarm.call_count == 2  # two ports
        assert 443 in probed["10.0.0.1"]["jarm"]
        assert 8443 in probed["10.0.0.1"]["jarm"]

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_skips_already_probed_ports(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                        mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                        tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [443, 8443])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        mock_jarm.return_value = "c0c" * 10 + "a" * 32
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {"10.0.0.1": {"jarm": {443}}}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        # Should only probe 8443 (443 already done)
        assert mock_jarm.call_count == 1
        mock_jarm.assert_called_once_with("10.0.0.1", 8443, timeout=1.0)

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_empty_hash_not_logged(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                    mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                    tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [443])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert 443 in probed["10.0.0.1"]["jarm"]
        if json_path.exists():
            content = json_path.read_text()
            assert "jarm_fingerprint" not in content

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_exception_marks_port_probed(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                          mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                          tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [443])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        mock_jarm.side_effect = OSError("Connection refused")
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert 443 in probed["10.0.0.1"]["jarm"]

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_skips_ip_with_all_ports_done(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                           mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                           tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [443, 8443])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {
            "10.0.0.1": {"jarm": {443, 8443}, "hassh": set(), "tcpfp": set()},
        }

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert mock_jarm.call_count == 0


# ─── _probe_cycle: HASSH phase ─────────────────────────────────────────────

class TestProbeCycleHASSH:

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_probes_ssh_ports(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                               mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                               tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [22, 2222])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
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

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert mock_hassh.call_count == 2
        assert 22 in probed["10.0.0.1"]["hassh"]
        assert 2222 in probed["10.0.0.1"]["hassh"]

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_hassh_writes_event(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                 mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                 tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [22])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
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

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert json_path.exists()
        content = json_path.read_text()
        assert "hassh_fingerprint" in content
        record = json.loads(content.strip())
        assert record["fields"]["hassh_server_hash"] == "b" * 32
        assert record["fields"]["ssh_banner"] == "SSH-2.0-Paramiko_3.0"

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_hassh_none_not_logged(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                    mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                    tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [22])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None  # No SSH server
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert 22 in probed["10.0.0.1"]["hassh"]
        if json_path.exists():
            content = json_path.read_text()
            assert "hassh_fingerprint" not in content

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_hassh_skips_already_probed(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                         mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                         tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [22, 2222])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {"10.0.0.1": {"hassh": {22}}}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert mock_hassh.call_count == 1  # only 2222
        mock_hassh.assert_called_once_with("10.0.0.1", 2222, timeout=1.0)

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_hassh_exception_marks_probed(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                           mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                           tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [22])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.side_effect = OSError("Connection refused")
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert 22 in probed["10.0.0.1"]["hassh"]


# ─── _probe_cycle: TCPFP phase ─────────────────────────────────────────────

class TestProbeCycleTCPFP:

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_probes_tcpfp_ports(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                 mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                 tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [80, 443])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = {
            "tcpfp_hash": "d" * 32,
            "tcpfp_raw": "64:65535:1:1460:7:1:1:M,N,W,N,N,T,S,E",
            "ttl": 64, "window_size": 65535, "df_bit": 1,
            "mss": 1460, "window_scale": 7, "sack_ok": 1,
            "timestamp": 1, "options_order": "M,N,W,N,N,T,S,E",
            "tos": 0, "dscp": 0, "ecn": 0, "server_isn": 0,
        }
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert mock_tcpfp.call_count == 2
        assert 80 in probed["10.0.0.1"]["tcpfp"]
        assert 443 in probed["10.0.0.1"]["tcpfp"]

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_tcpfp_writes_event_with_all_fields(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                                  mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                                  tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [443])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = {
            "tcpfp_hash": "e" * 32,
            "tcpfp_raw": "128:8192:1:1460:8:1:0:M,N,W,N,N,S",
            "ttl": 128, "window_size": 8192, "df_bit": 1,
            "mss": 1460, "window_scale": 8, "sack_ok": 1,
            "timestamp": 0, "options_order": "M,N,W,N,N,S",
            "tos": 0, "dscp": 0, "ecn": 0, "server_isn": 0,
        }
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        content = json_path.read_text()
        assert "tcpfp_fingerprint" in content
        record = json.loads(content.strip())
        assert record["fields"]["tcpfp_hash"] == "e" * 32
        assert record["fields"]["ttl"] == "128"
        assert record["fields"]["window_size"] == "8192"
        assert record["fields"]["options_order"] == "M,N,W,N,N,S"

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_tcpfp_none_not_logged(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                    mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                    tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [443])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        assert 443 in probed["10.0.0.1"]["tcpfp"]
        if json_path.exists():
            content = json_path.read_text()
            assert "tcpfp_fingerprint" not in content


# ─── Probe type isolation ───────────────────────────────────────────────────

class TestProbeTypeIsolation:

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_jarm_does_not_mark_hassh(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                       mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                       tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """JARM probing port 2222 should not mark HASSH port 2222 as done."""
        monkeypatch.setattr(JarmProbe, "default_ports", [2222])
        monkeypatch.setattr(HasshProbe, "default_ports", [2222])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

        # Both should be called
        assert mock_jarm.call_count == 1
        assert mock_hassh.call_count == 1
        assert 2222 in probed["10.0.0.1"]["jarm"]
        assert 2222 in probed["10.0.0.1"]["hassh"]

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_all_three_probes_run(self, mock_jarm: MagicMock, mock_hassh: MagicMock,
                                   mock_tcpfp: MagicMock, mock_ipv6: MagicMock,
                                   tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(JarmProbe, "default_ports", [443])
        monkeypatch.setattr(HasshProbe, "default_ports", [22])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [80])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, dict[str, set[int]]] = {}

        _probe_cycle(targets, probed, log_path, json_path, timeout=1.0)

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
        assert "relay@55555" in log_content

        json_content = json_path.read_text()
        record = json.loads(json_content.strip())
        assert record["event_type"] == "test_event"
        assert record["service"] == "prober"
        assert record["fields"]["target_ip"] == "10.0.0.1"


# ─── _probe_cycle: TLS certificate capture ────────────────────────────────
# TlsCertProbe is now an independent registered probe (priority=200).
# It calls fetch_leaf_cert directly — not coupled to JARM outcome.

_CERT_STUB = {
    "subject_cn": "evil.example.com",
    "issuer": "CN=evil.example.com",
    "self_signed": True,
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z",
    "sans": ["evil.example.com", "c2.example.com"],
    "cert_sha256": "ab" * 32,
}


class TestProbeCycleTLSCert:

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tlscert_probe.fetch_leaf_cert")
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_cert_event_emitted_for_tls_port(
        self,
        mock_jarm: MagicMock,
        mock_hassh: MagicMock,
        mock_tcpfp: MagicMock,
        mock_cert: MagicMock,
        mock_ipv6: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """TlsCertProbe runs independently; a successful fetch writes a tls_certificate event."""
        from decnet.prober.probes.tlscert_probe import TlsCertProbe
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        monkeypatch.setattr(TlsCertProbe, "default_ports", [443])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        mock_cert.return_value = _CERT_STUB
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        _probe_cycle({"10.0.0.1"}, {}, log_path, json_path, timeout=1.0)

        mock_cert.assert_called_once_with("10.0.0.1", 443, timeout=1.0)
        records = [json.loads(line) for line in json_path.read_text().splitlines() if line]
        cert_records = [r for r in records if r["event_type"] == "tls_certificate"]
        assert len(cert_records) == 1
        f = cert_records[0]["fields"]
        assert f["target_ip"] == "10.0.0.1"
        assert f["target_port"] == "443"
        assert f["subject_cn"] == "evil.example.com"
        assert f["self_signed"] == "true"
        assert f["sans"] == "evil.example.com,c2.example.com"
        assert f["cert_sha256"] == "ab" * 32

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tlscert_probe.fetch_leaf_cert", return_value=None)
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_cert_skipped_when_fetch_returns_none(
        self,
        mock_jarm: MagicMock,
        mock_hassh: MagicMock,
        mock_tcpfp: MagicMock,
        mock_cert: MagicMock,
        mock_ipv6: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """fetch_leaf_cert returning None → no tls_certificate event."""
        from decnet.prober.probes.tlscert_probe import TlsCertProbe
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        monkeypatch.setattr(TlsCertProbe, "default_ports", [443])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        _probe_cycle({"10.0.0.1"}, {}, log_path, json_path, timeout=1.0)

        mock_cert.assert_called_once_with("10.0.0.1", 443, timeout=1.0)
        if json_path.exists():
            content = json_path.read_text()
            assert "tls_certificate" not in content

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tlscert_probe.fetch_leaf_cert")
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_cert_fetch_crash_does_not_break_phase(
        self,
        mock_jarm: MagicMock,
        mock_hassh: MagicMock,
        mock_tcpfp: MagicMock,
        mock_cert: MagicMock,
        mock_ipv6: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """fetch_leaf_cert crash is caught by _run_probe; both ports still marked probed."""
        from decnet.prober.probes.tlscert_probe import TlsCertProbe
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        monkeypatch.setattr(TlsCertProbe, "default_ports", [443, 8443])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        mock_cert.side_effect = RuntimeError("unexpected")
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        _probe_cycle({"10.0.0.1"}, {}, log_path, json_path, timeout=1.0)

        assert mock_cert.call_count == 2

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tlscert_probe.fetch_leaf_cert")
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_cert_publish_fn_called(
        self,
        mock_jarm: MagicMock,
        mock_hassh: MagicMock,
        mock_tcpfp: MagicMock,
        mock_cert: MagicMock,
        mock_ipv6: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """publish_fn receives a 'tls_certificate' event on successful cert capture."""
        from decnet.prober.probes.tlscert_probe import TlsCertProbe
        monkeypatch.setattr(JarmProbe, "default_ports", [])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        monkeypatch.setattr(TlsCertProbe, "default_ports", [443])
        mock_jarm.return_value = JARM_EMPTY_HASH
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        mock_cert.return_value = {
            "subject_cn": "cn",
            "issuer": "CN=cn",
            "self_signed": True,
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2027-01-01T00:00:00Z",
            "sans": [],
            "cert_sha256": "cd" * 32,
        }
        published: list[tuple[str, dict]] = []

        def publish(kind: str, payload: dict) -> None:
            published.append((kind, payload))

        _probe_cycle(
            {"10.0.0.1"}, {},
            tmp_path / "decnet.log", tmp_path / "decnet.json",
            timeout=1.0, publish_fn=publish,
        )

        cert_pubs = [p for p in published if p[0] == "tls_certificate"]
        assert len(cert_pubs) == 1
        assert cert_pubs[0][1]["attacker_ip"] == "10.0.0.1"
        assert cert_pubs[0][1]["port"] == 443
        assert cert_pubs[0][1]["cert_sha256"] == "cd" * 32
        assert cert_pubs[0][1]["self_signed"] is True

    @patch("decnet.prober.ipv6_leak._route_info", return_value=(False, None))
    @patch("decnet.prober.probes.tlscert_probe.fetch_leaf_cert")
    @patch("decnet.prober.probes.tcpfp.tcp_fingerprint")
    @patch("decnet.prober.probes.hassh.hassh_server")
    @patch("decnet.prober.probes.jarm.jarm_hash")
    def test_cert_independent_of_jarm_result(
        self,
        mock_jarm: MagicMock,
        mock_hassh: MagicMock,
        mock_tcpfp: MagicMock,
        mock_cert: MagicMock,
        mock_ipv6: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ):
        """TlsCertProbe runs regardless of JARM outcome (independent registry probe)."""
        from decnet.prober.probes.tlscert_probe import TlsCertProbe
        monkeypatch.setattr(JarmProbe, "default_ports", [443])
        monkeypatch.setattr(HasshProbe, "default_ports", [])
        monkeypatch.setattr(TcpfpProbe, "default_ports", [])
        monkeypatch.setattr(TlsCertProbe, "default_ports", [443])
        mock_jarm.return_value = JARM_EMPTY_HASH  # port doesn't speak TLS per JARM
        mock_hassh.return_value = None
        mock_tcpfp.return_value = None
        mock_cert.return_value = _CERT_STUB
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        _probe_cycle({"10.0.0.1"}, {}, log_path, json_path, timeout=1.0)

        # TlsCertProbe still called despite empty JARM hash
        mock_cert.assert_called_once_with("10.0.0.1", 443, timeout=1.0)
