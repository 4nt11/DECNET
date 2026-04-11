"""Tests for the host-side Docker log collector."""

import json
from types import SimpleNamespace
from unittest.mock import patch
from decnet.web.collector import parse_rfc5424, is_service_container, is_service_event

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


class TestIsServiceContainer:
    def test_known_container_returns_true(self):
        with patch("decnet.web.collector._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_container(_make_container("omega-decky-http")) is True
            assert is_service_container(_make_container("omega-decky-smtp")) is True
            assert is_service_container(_make_container("relay-decky-ftp")) is True

    def test_base_container_returns_false(self):
        with patch("decnet.web.collector._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_container(_make_container("omega-decky")) is False

    def test_unrelated_container_returns_false(self):
        with patch("decnet.web.collector._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_container(_make_container("nginx")) is False

    def test_strips_leading_slash(self):
        with patch("decnet.web.collector._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_container(_make_container("/omega-decky-http")) is True
            assert is_service_container(_make_container("/omega-decky")) is False

    def test_no_state_returns_false(self):
        with patch("decnet.web.collector._load_service_container_names", return_value=set()):
            assert is_service_container(_make_container("omega-decky-http")) is False


class TestIsServiceEvent:
    def test_known_service_event_returns_true(self):
        with patch("decnet.web.collector._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_event({"name": "omega-decky-smtp"}) is True

    def test_base_event_returns_false(self):
        with patch("decnet.web.collector._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_event({"name": "omega-decky"}) is False

    def test_unrelated_event_returns_false(self):
        with patch("decnet.web.collector._load_service_container_names", return_value=_KNOWN_NAMES):
            assert is_service_event({"name": "nginx"}) is False

    def test_no_state_returns_false(self):
        with patch("decnet.web.collector._load_service_container_names", return_value=set()):
            assert is_service_event({"name": "omega-decky-smtp"}) is False
