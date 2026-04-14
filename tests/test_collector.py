"""Tests for the host-side Docker log collector."""

import json
import asyncio
import pytest
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
from decnet.collector import parse_rfc5424, is_service_container, is_service_event
from decnet.collector.worker import (
    _stream_container,
    _load_service_container_names,
    log_collector_worker
)

_KNOWN_NAMES = {"omega-decky-http", "omega-decky-smtp", "relay-decky-ftp"}


def _make_container(name="omega-decky-http"):
    return SimpleNamespace(name=name)


class TestParseRfc5424:
    def _make_line(self, fields_str="", msg=""):
        sd = f"[decnet@55555 {fields_str}]" if fields_str else "-"
        suffix = f" {msg}" if msg else ""
        return f"<134>1 2024-01-15T12:00:00+00:00 decky-01 http - request {sd}{suffix}"

    def test_returns_none_for_non_decnet_line(self):
        assert parse_rfc5424("not a syslog line") is None

    def test_returns_none_for_empty_line(self):
        assert parse_rfc5424("") is None

    def test_parses_basic_fields(self):
        line = self._make_line()
        result = parse_rfc5424(line)
        assert result is not None
        assert result["decky"] == "decky-01"
        assert result["service"] == "http"
        assert result["event_type"] == "request"

    def test_parses_structured_data_fields(self):
        line = self._make_line('src_ip="1.2.3.4" method="GET" path="/login"')
        result = parse_rfc5424(line)
        assert result is not None
        assert result["fields"]["src_ip"] == "1.2.3.4"
        assert result["fields"]["method"] == "GET"
        assert result["fields"]["path"] == "/login"

    def test_extracts_attacker_ip_from_src_ip(self):
        line = self._make_line('src_ip="10.0.0.5"')
        result = parse_rfc5424(line)
        assert result["attacker_ip"] == "10.0.0.5"

    def test_extracts_attacker_ip_from_src(self):
        line = self._make_line('src="10.0.0.5"')
        result = parse_rfc5424(line)
        assert result["attacker_ip"] == "10.0.0.5"

    def test_extracts_attacker_ip_from_client_ip(self):
        line = self._make_line('client_ip="10.0.0.7"')
        result = parse_rfc5424(line)
        assert result["attacker_ip"] == "10.0.0.7"

    def test_extracts_attacker_ip_from_remote_ip(self):
        line = self._make_line('remote_ip="10.0.0.8"')
        result = parse_rfc5424(line)
        assert result["attacker_ip"] == "10.0.0.8"

    def test_extracts_attacker_ip_from_ip(self):
        line = self._make_line('ip="10.0.0.9"')
        result = parse_rfc5424(line)
        assert result["attacker_ip"] == "10.0.0.9"

    def test_attacker_ip_defaults_to_unknown(self):
        line = self._make_line('user="admin"')
        result = parse_rfc5424(line)
        assert result["attacker_ip"] == "Unknown"

    def test_parses_msg(self):
        line = self._make_line(msg="hello world")
        result = parse_rfc5424(line)
        assert result["msg"] == "hello world"

    def test_nilvalue_sd_with_msg(self):
        line = "<134>1 2024-01-15T12:00:00+00:00 decky-01 http - request - some message"
        result = parse_rfc5424(line)
        assert result is not None
        assert result["msg"] == "some message"
        assert result["fields"] == {}

    def test_raw_line_preserved(self):
        line = self._make_line('src_ip="1.2.3.4"')
        result = parse_rfc5424(line)
        assert result["raw_line"] == line

    def test_timestamp_formatted(self):
        line = self._make_line()
        result = parse_rfc5424(line)
        assert result["timestamp"] == "2024-01-15 12:00:00"

    def test_unescapes_sd_values(self):
        line = self._make_line(r'path="/foo\"bar"')
        result = parse_rfc5424(line)
        assert result["fields"]["path"] == '/foo"bar'

    def test_result_json_serializable(self):
        line = self._make_line('src_ip="1.2.3.4" username="admin" password="s3cr3t"')
        result = parse_rfc5424(line)
        # Should not raise
        json.dumps(result)

    def test_invalid_timestamp_preserved_as_is(self):
        line = "<134>1 not-a-date decky-01 http - request -"
        result = parse_rfc5424(line)
        assert result is not None
        assert result["timestamp"] == "not-a-date"

    def test_sd_rest_is_plain_text(self):
        # When SD starts with neither '-' nor '[', treat as msg
        line = "<134>1 2024-01-15T12:00:00+00:00 decky-01 http - request hello world"
        result = parse_rfc5424(line)
        assert result is not None
        assert result["msg"] == "hello world"

    def test_sd_with_msg_after_bracket(self):
        line = '<134>1 2024-01-15T12:00:00+00:00 decky-01 http - request [decnet@55555 src_ip="1.2.3.4"] login attempt'
        result = parse_rfc5424(line)
        assert result is not None
        assert result["fields"]["src_ip"] == "1.2.3.4"
        assert result["msg"] == "login attempt"


    def test_bash_cmd_normalized_to_ssh_command(self):
        line = '<14>1 2026-04-14T05:48:12.628417+00:00 SRV-BRAVO-13 bash - - -  CMD uid=0 pwd=/root cmd=ls /var/www/html'
        result = parse_rfc5424(line)
        assert result is not None
        assert result["service"] == "ssh"
        assert result["event_type"] == "command"
        assert result["fields"]["command"] == "ls /var/www/html"
        assert result["fields"]["uid"] == "0"
        assert result["fields"]["pwd"] == "/root"

    def test_bash_cmd_simple_command(self):
        line = '<14>1 2026-04-14T05:48:13.332072+00:00 SRV-BRAVO-13 bash - - -  CMD uid=0 pwd=/root cmd=ls'
        result = parse_rfc5424(line)
        assert result is not None
        assert result["service"] == "ssh"
        assert result["event_type"] == "command"
        assert result["fields"]["command"] == "ls"

    def test_bash_non_cmd_not_normalized(self):
        line = '<14>1 2026-04-14T05:48:12.628417+00:00 SRV-BRAVO-13 bash - - - some other bash message'
        result = parse_rfc5424(line)
        assert result is not None
        assert result["service"] == "bash"
        assert result["event_type"] == "-"


class TestIsServiceContainer:
    def test_known_container_returns_true(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_container(_make_container("omega-decky-http")) is True
            assert is_service_container(_make_container("omega-decky-smtp")) is True
            assert is_service_container(_make_container("relay-decky-ftp")) is True

    def test_base_container_returns_false(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_container(_make_container("omega-decky")) is False

    def test_unrelated_container_returns_false(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_container(_make_container("nginx")) is False

    def test_strips_leading_slash(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_container(_make_container("/omega-decky-http")) is True
            assert is_service_container(_make_container("/omega-decky")) is False

    def test_no_state_returns_false(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=set()):
            assert is_service_container(_make_container("omega-decky-http")) is False

    def test_string_argument(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_container("omega-decky-http") is True
            assert is_service_container("/omega-decky-http") is True
            assert is_service_container("nginx") is False


class TestIsServiceEvent:
    def test_known_service_event_returns_true(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_event({"name": "omega-decky-smtp"}) is True

    def test_base_event_returns_false(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_event({"name": "omega-decky"}) is False

    def test_unrelated_event_returns_false(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_event({"name": "nginx"}) is False

    def test_no_state_returns_false(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=set()):
            assert is_service_event({"name": "omega-decky-smtp"}) is False

    def test_strips_leading_slash(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_event({"name": "/omega-decky-smtp"}) is True

    def test_empty_name(self):
        with patch("decnet.collector.worker._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_event({"name": ""}) is False
            assert is_service_event({}) is False


class TestLoadServiceContainerNames:
    def test_with_valid_state(self, tmp_path, monkeypatch):
        import decnet.config
        from decnet.config import DeckyConfig, DecnetConfig
        state_file = tmp_path / "state.json"
        config = DecnetConfig(
            mode="unihost", interface="eth0", subnet="192.168.1.0/24",
            gateway="192.168.1.1",
            deckies=[
                DeckyConfig(name="decky-01", ip="192.168.1.10", services=["ssh", "http"],
                            distro="debian", base_image="debian", hostname="test",
                            build_base="debian:bookworm-slim"),
            ],
        )
        state_file.write_text(json.dumps({
            "config": config.model_dump(),
            "compose_path": "test.yml",
        }))
        monkeypatch.setattr(decnet.config, "STATE_FILE", state_file)
        names = _load_service_container_names()
        assert names == {"decky-01-ssh", "decky-01-http"}

    def test_no_state(self, tmp_path, monkeypatch):
        import decnet.config
        state_file = tmp_path / "nonexistent.json"
        monkeypatch.setattr(decnet.config, "STATE_FILE", state_file)
        names = _load_service_container_names()
        assert names == set()


class TestStreamContainer:
    def test_streams_rfc5424_lines(self, tmp_path):
        log_path = tmp_path / "test.log"
        json_path = tmp_path / "test.json"

        mock_container = MagicMock()
        rfc_line = '<134>1 2024-01-15T12:00:00+00:00 decky-01 ssh - auth [decnet@55555 src_ip="1.2.3.4"] login\n'
        mock_container.logs.return_value = [rfc_line.encode("utf-8")]

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        with patch("docker.from_env", return_value=mock_client):
            _stream_container("test-id", log_path, json_path)

        assert log_path.exists()
        log_content = log_path.read_text()
        assert "decky-01" in log_content

        assert json_path.exists()
        json_content = json_path.read_text().strip()
        parsed = json.loads(json_content)
        assert parsed["service"] == "ssh"

    def test_handles_non_rfc5424_lines(self, tmp_path):
        log_path = tmp_path / "test.log"
        json_path = tmp_path / "test.json"

        mock_container = MagicMock()
        mock_container.logs.return_value = [b"just a plain log line\n"]

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        with patch("docker.from_env", return_value=mock_client):
            _stream_container("test-id", log_path, json_path)

        assert log_path.exists()
        assert json_path.read_text() == ""  # No JSON written for non-RFC lines

    def test_handles_docker_error(self, tmp_path):
        log_path = tmp_path / "test.log"
        json_path = tmp_path / "test.json"

        mock_client = MagicMock()
        mock_client.containers.get.side_effect = Exception("Container not found")

        with patch("docker.from_env", return_value=mock_client):
            _stream_container("bad-id", log_path, json_path)

        # Should not raise, just log the error

    def test_skips_empty_lines(self, tmp_path):
        log_path = tmp_path / "test.log"
        json_path = tmp_path / "test.json"

        mock_container = MagicMock()
        mock_container.logs.return_value = [b"\n\n\n"]

        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        with patch("docker.from_env", return_value=mock_client):
            _stream_container("test-id", log_path, json_path)

        assert log_path.read_text() == ""


class TestLogCollectorWorker:
    @pytest.mark.asyncio
    async def test_worker_initial_discovery(self, tmp_path):
        log_file = str(tmp_path / "decnet.log")

        mock_container = MagicMock()
        mock_container.id = "c1"
        mock_container.name = "/s-1"
        # Mock labels to satisfy is_service_container
        mock_container.labels = {"com.docker.compose.project": "decnet"}

        mock_client = MagicMock()
        mock_client.containers.list.return_value = [mock_container]
        # Make events return an empty generator/iterator immediately
        mock_client.events.return_value = iter([])

        with patch("docker.from_env", return_value=mock_client), \
             patch("decnet.collector.worker.is_service_container", return_value=True):
            # Run with a short task timeout because it loops
            try:
                await asyncio.wait_for(log_collector_worker(log_file), timeout=0.1)
            except (asyncio.TimeoutError, StopIteration):
                pass

        # Should have tried to list and watch events
        mock_client.containers.list.assert_called_once()

    @pytest.mark.asyncio
    async def test_worker_handles_events(self, tmp_path):
        log_file = str(tmp_path / "decnet.log")

        mock_client = MagicMock()
        mock_client.containers.list.return_value = []

        event = {
            "id": "c2",
            "Actor": {"Attributes": {"name": "s-2", "com.docker.compose.project": "decnet"}}
        }
        mock_client.events.return_value = iter([event])

        with patch("docker.from_env", return_value=mock_client), \
             patch("decnet.collector.worker.is_service_event", return_value=True):
            try:
                await asyncio.wait_for(log_collector_worker(log_file), timeout=0.1)
            except (asyncio.TimeoutError, StopIteration):
                pass

        mock_client.events.assert_called_once()

    @pytest.mark.asyncio
    async def test_worker_exception_handling(self, tmp_path):
        log_file = str(tmp_path / "decnet.log")
        mock_client = MagicMock()
        mock_client.containers.list.side_effect = Exception("Docker down")

        with patch("docker.from_env", return_value=mock_client):
            # Should not raise
            await log_collector_worker(log_file)

