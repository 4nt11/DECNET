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
    _should_ingest,
    _reset_rate_limiter,
    log_collector_worker,
)

_KNOWN_NAMES = {"omega-decky-http", "omega-decky-smtp", "relay-decky-ftp"}


def _make_container(name="omega-decky-http"):
    return SimpleNamespace(name=name)


class TestParseRfc5424:
    def _make_line(self, fields_str="", msg=""):
        sd = f"[relay@55555 {fields_str}]" if fields_str else "-"
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

    def test_parses_line_with_real_procid(self):
        """sshd/sudo log via native syslog, so rsyslog fills PROCID with the
        real PID instead of NILVALUE. The parser must accept either form."""
        line = (
            "<38>1 2026-04-18T08:27:21.862365+00:00 omega-decky sshd 940 - - "
            "Accepted password for root from 192.168.1.5 port 43210 ssh2"
        )
        result = parse_rfc5424(line)
        assert result is not None
        assert result["decky"] == "omega-decky"
        assert result["service"] == "sshd"
        assert "Accepted password" in result["msg"]
        assert result["attacker_ip"] == "Unknown"  # no key=value in this msg

    def test_extracts_attacker_ip_from_msg_body_kv(self):
        """SSH container's bash PROMPT_COMMAND uses `logger -t bash "CMD ... src=IP ..."`
        which produces an RFC 5424 line with NILVALUE SD — the IP lives in the
        free-form msg, not in SD params. The collector should still pick it up."""
        line = (
            "<134>1 2024-01-15T12:00:00+00:00 decky-01 bash - - - "
            "CMD uid=0 user=root src=198.51.100.7 pwd=/root cmd=ls -la"
        )
        result = parse_rfc5424(line)
        assert result is not None
        assert result["attacker_ip"] == "198.51.100.7"
        # `fields` stays empty — the frontend's parseEventBody renders kv
        # pairs straight from msg; we don't want duplicate pills.
        assert result["fields"] == {}
        assert "CMD uid=0" in result["msg"]

    def test_sd_ip_wins_over_msg_body(self):
        """If SD params carry an IP, the msg-body fallback must not overwrite it."""
        line = (
            '<134>1 2024-01-15T12:00:00+00:00 decky-01 ssh - login '
            '[relay@55555 src_ip="1.2.3.4"] rogue src=9.9.9.9 entry'
        )
        result = parse_rfc5424(line)
        assert result["attacker_ip"] == "1.2.3.4"
        # SD wins; `src=` from msg isn't folded into fields (msg retains it).
        assert result["fields"]["src_ip"] == "1.2.3.4"
        assert "src" not in result["fields"]

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
        line = '<134>1 2024-01-15T12:00:00+00:00 decky-01 http - request [relay@55555 src_ip="1.2.3.4"] login attempt'
        result = parse_rfc5424(line)
        assert result is not None
        assert result["fields"]["src_ip"] == "1.2.3.4"
        assert result["msg"] == "login attempt"


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
        rfc_line = '<134>1 2024-01-15T12:00:00+00:00 decky-01 ssh - auth [relay@55555 src_ip="1.2.3.4"] login\n'
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
        # JSON file is only created when RFC5424 lines are parsed — not for plain lines.
        assert not json_path.exists() or json_path.read_text() == ""

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

        # All lines were empty — no file is created (lazy open).
        assert not log_path.exists() or log_path.read_text() == ""

    def test_log_file_recreated_after_deletion(self, tmp_path):
        log_path = tmp_path / "test.log"
        json_path = tmp_path / "test.json"

        line1 = b"first line\n"
        line2 = b"second line\n"

        def _chunks():
            yield line1
            log_path.unlink()   # simulate deletion between writes
            yield line2

        mock_container = MagicMock()
        mock_container.logs.return_value = _chunks()
        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        with patch("docker.from_env", return_value=mock_client):
            _stream_container("test-id", log_path, json_path)

        assert log_path.exists(), "log file must be recreated after deletion"
        content = log_path.read_text()
        assert "second line" in content

    def test_json_file_recreated_after_deletion(self, tmp_path):
        log_path = tmp_path / "test.log"
        json_path = tmp_path / "test.json"

        rfc_line = (
            '<134>1 2024-01-15T12:00:00+00:00 decky-01 ssh - auth '
            '[relay@55555 src_ip="1.2.3.4"] login\n'
        )
        encoded = rfc_line.encode("utf-8")

        def _chunks():
            yield encoded
            # Remove the json file between writes; the second RFC line should
            # trigger a fresh file open.
            if json_path.exists():
                json_path.unlink()
            yield encoded

        mock_container = MagicMock()
        mock_container.logs.return_value = _chunks()
        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        with patch("docker.from_env", return_value=mock_client):
            _stream_container("test-id", log_path, json_path)

        assert json_path.exists(), "json file must be recreated after deletion"
        lines = [l for l in json_path.read_text().splitlines() if l.strip()]
        assert len(lines) >= 1

    def test_rotated_file_detected(self, tmp_path):
        """Simulate logrotate: rename old file away, new write should go to a fresh file."""
        log_path = tmp_path / "test.log"
        json_path = tmp_path / "test.json"

        line1 = b"before rotation\n"
        line2 = b"after rotation\n"
        rotated = tmp_path / "test.log.1"

        def _chunks():
            yield line1
            log_path.rename(rotated)   # logrotate renames old file
            yield line2

        mock_container = MagicMock()
        mock_container.logs.return_value = _chunks()
        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        with patch("docker.from_env", return_value=mock_client):
            _stream_container("test-id", log_path, json_path)

        assert log_path.exists(), "new log file must be created after rotation"
        assert "after rotation" in log_path.read_text()
        assert "before rotation" in rotated.read_text()


class TestIngestRateLimiter:
    def setup_method(self):
        _reset_rate_limiter()

    def _event(self, event_type="connect", attacker_ip="1.2.3.4",
               decky="decky-01", service="ssh"):
        return {
            "event_type": event_type,
            "attacker_ip": attacker_ip,
            "decky": decky,
            "service": service,
        }

    def test_non_limited_event_types_always_pass(self):
        # login_attempt / request / etc. carry distinguishing payload — never deduped.
        for _ in range(5):
            assert _should_ingest(self._event(event_type="login_attempt")) is True
            assert _should_ingest(self._event(event_type="request")) is True

    def test_first_connect_passes(self):
        assert _should_ingest(self._event()) is True

    def test_duplicate_connect_within_window_is_dropped(self):
        assert _should_ingest(self._event()) is True
        assert _should_ingest(self._event()) is False
        assert _should_ingest(self._event()) is False

    def test_different_attackers_tracked_independently(self):
        assert _should_ingest(self._event(attacker_ip="1.1.1.1")) is True
        assert _should_ingest(self._event(attacker_ip="2.2.2.2")) is True

    def test_different_deckies_tracked_independently(self):
        assert _should_ingest(self._event(decky="a")) is True
        assert _should_ingest(self._event(decky="b")) is True

    def test_different_services_tracked_independently(self):
        assert _should_ingest(self._event(service="ssh")) is True
        assert _should_ingest(self._event(service="http")) is True

    def test_disconnect_and_connect_tracked_independently(self):
        assert _should_ingest(self._event(event_type="connect")) is True
        assert _should_ingest(self._event(event_type="disconnect")) is True

    def test_window_expiry_allows_next_event(self, monkeypatch):
        import decnet.collector.worker as worker
        t = [1000.0]
        monkeypatch.setattr(worker.time, "monotonic", lambda: t[0])
        assert _should_ingest(self._event()) is True
        assert _should_ingest(self._event()) is False
        # Advance past 1-second window.
        t[0] += 1.5
        assert _should_ingest(self._event()) is True

    def test_window_zero_disables_limiter(self, monkeypatch):
        import decnet.collector.worker as worker
        monkeypatch.setattr(worker, "_RL_WINDOW_SEC", 0.0)
        for _ in range(10):
            assert _should_ingest(self._event()) is True

    def test_raw_log_gets_all_lines_json_dedupes(self, tmp_path):
        """End-to-end: duplicates hit the .log file but NOT the .json stream."""
        log_path = tmp_path / "test.log"
        json_path = tmp_path / "test.json"
        line = (
            '<134>1 2024-01-15T12:00:00+00:00 decky-01 ssh - connect '
            '[relay@55555 src_ip="1.2.3.4"]\n'
        )
        payload = (line * 5).encode("utf-8")

        mock_container = MagicMock()
        mock_container.logs.return_value = [payload]
        mock_client = MagicMock()
        mock_client.containers.get.return_value = mock_container

        with patch("docker.from_env", return_value=mock_client):
            _stream_container("test-id", log_path, json_path)

        # Raw log: all 5 lines preserved (forensic fidelity).
        assert log_path.read_text().count("\n") == 5
        # JSON ingest: only the first one written (4 dropped by the limiter).
        json_lines = [l for l in json_path.read_text().splitlines() if l.strip()]
        assert len(json_lines) == 1

    def test_gc_trims_oversized_map(self, monkeypatch):
        import decnet.collector.worker as worker
        # Seed the map with stale entries, then push past the cap.
        monkeypatch.setattr(worker, "_RL_MAX_ENTRIES", 10)
        t = [1000.0]
        monkeypatch.setattr(worker.time, "monotonic", lambda: t[0])
        for i in range(9):
            assert _should_ingest(self._event(attacker_ip=f"10.0.0.{i}")) is True
        # Jump well past 60 windows to make prior entries stale.
        t[0] += 1000.0
        # This insertion pushes len to 10; GC triggers on >10 so stays.
        assert _should_ingest(self._event(attacker_ip="10.0.0.99")) is True
        assert _should_ingest(self._event(attacker_ip="10.0.0.100")) is True
        # After the map exceeds the cap, stale entries must be purged.
        assert len(worker._rl_last) < 10


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

