"""Tests for the host-side Docker log collector."""

import json
from types import SimpleNamespace
from decnet.web.collector import parse_rfc5424, is_service_container, is_service_event


def _make_container(project="decnet", depends_on="omega-decky:service_started:false"):
    """Return a mock container object with Compose labels."""
    return SimpleNamespace(
        name="omega-decky-http",
        labels={
            "com.docker.compose.project": project,
            "com.docker.compose.depends_on": depends_on,
        },
    )


def _make_base_container():
    """Return a mock base container (no depends_on)."""
    return SimpleNamespace(
        name="omega-decky",
        labels={
            "com.docker.compose.project": "decnet",
            "com.docker.compose.depends_on": "",
        },
    )


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
    def test_service_container_returns_true(self):
        assert is_service_container(_make_container()) is True

    def test_base_container_returns_false(self):
        assert is_service_container(_make_base_container()) is False

    def test_different_decky_name_styles(self):
        # omega-decky style (ini section name)
        assert is_service_container(_make_container(depends_on="omega-decky:service_started:false")) is True
        # relay-decky style
        assert is_service_container(_make_container(depends_on="relay-decky:service_started:false")) is True

    def test_wrong_project_returns_false(self):
        assert is_service_container(_make_container(project="someother")) is False

    def test_no_labels_returns_false(self):
        c = SimpleNamespace(name="nginx", labels={})
        assert is_service_container(c) is False


class TestIsServiceEvent:
    def _make_attrs(self, project="decnet", depends_on="omega-decky:service_started:false"):
        return {
            "com.docker.compose.project": project,
            "com.docker.compose.depends_on": depends_on,
            "name": "omega-decky-smtp",
        }

    def test_service_event_returns_true(self):
        assert is_service_event(self._make_attrs()) is True

    def test_base_event_returns_false(self):
        assert is_service_event(self._make_attrs(depends_on="")) is False

    def test_wrong_project_returns_false(self):
        assert is_service_event(self._make_attrs(project="other")) is False

    def test_unrelated_event_returns_false(self):
        assert is_service_event({"name": "nginx"}) is False
