"""
Tests for the prober worker — target discovery from the log stream and
probe cycle behavior.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from decnet.prober.jarm import JARM_EMPTY_HASH
from decnet.prober.worker import (
    DEFAULT_PROBE_PORTS,
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


# ─── _probe_cycle ────────────────────────────────────────────────────────────

class TestProbeCycle:

    @patch("decnet.prober.worker.jarm_hash")
    def test_probes_new_ips(self, mock_jarm: MagicMock, tmp_path: Path):
        mock_jarm.return_value = "c0c" * 10 + "a" * 32  # fake 62-char hash
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, set[int]] = {}

        _probe_cycle(targets, probed, [443, 8443], log_path, json_path, timeout=1.0)

        assert mock_jarm.call_count == 2  # two ports
        assert 443 in probed["10.0.0.1"]
        assert 8443 in probed["10.0.0.1"]

    @patch("decnet.prober.worker.jarm_hash")
    def test_skips_already_probed_ports(self, mock_jarm: MagicMock, tmp_path: Path):
        mock_jarm.return_value = "c0c" * 10 + "a" * 32
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, set[int]] = {"10.0.0.1": {443}}

        _probe_cycle(targets, probed, [443, 8443], log_path, json_path, timeout=1.0)

        # Should only probe 8443 (443 already done)
        assert mock_jarm.call_count == 1
        mock_jarm.assert_called_once_with("10.0.0.1", 8443, timeout=1.0)

    @patch("decnet.prober.worker.jarm_hash")
    def test_empty_hash_not_logged(self, mock_jarm: MagicMock, tmp_path: Path):
        """All-zeros JARM hash (no TLS server) should not be written as a jarm_fingerprint event."""
        mock_jarm.return_value = JARM_EMPTY_HASH
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, set[int]] = {}

        _probe_cycle(targets, probed, [443], log_path, json_path, timeout=1.0)

        # Port should be marked as probed
        assert 443 in probed["10.0.0.1"]
        # But no jarm_fingerprint event should be written
        if json_path.exists():
            content = json_path.read_text()
            assert "jarm_fingerprint" not in content

    @patch("decnet.prober.worker.jarm_hash")
    def test_exception_marks_port_probed(self, mock_jarm: MagicMock, tmp_path: Path):
        mock_jarm.side_effect = OSError("Connection refused")
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, set[int]] = {}

        _probe_cycle(targets, probed, [443], log_path, json_path, timeout=1.0)

        # Port marked as probed to avoid infinite retries
        assert 443 in probed["10.0.0.1"]

    @patch("decnet.prober.worker.jarm_hash")
    def test_skips_ip_with_all_ports_done(self, mock_jarm: MagicMock, tmp_path: Path):
        log_path = tmp_path / "decnet.log"
        json_path = tmp_path / "decnet.json"

        targets = {"10.0.0.1"}
        probed: dict[str, set[int]] = {"10.0.0.1": {443, 8443}}

        _probe_cycle(targets, probed, [443, 8443], log_path, json_path, timeout=1.0)

        assert mock_jarm.call_count == 0


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
