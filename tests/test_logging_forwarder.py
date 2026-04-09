"""
Tests for decnet.logging.forwarder — parse_log_target, probe_log_target.
"""
import socket
from unittest.mock import MagicMock, patch

import pytest

from decnet.logging.forwarder import parse_log_target, probe_log_target


class TestParseLogTarget:
    def test_valid_ip_port(self):
        host, port = parse_log_target("192.168.1.5:5140")
        assert host == "192.168.1.5"
        assert port == 5140

    def test_valid_hostname_port(self):
        host, port = parse_log_target("logstash.internal:9600")
        assert host == "logstash.internal"
        assert port == 9600

    def test_no_colon_raises(self):
        with pytest.raises(ValueError, match="Invalid log_target"):
            parse_log_target("192.168.1.5")

    def test_non_digit_port_raises(self):
        with pytest.raises(ValueError, match="Invalid log_target"):
            parse_log_target("192.168.1.5:syslog")

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            parse_log_target("")

    def test_multiple_colons_uses_last_as_port(self):
        # IPv6-style or hostname with colons — rsplit takes the last segment
        host, port = parse_log_target("::1:514")
        assert port == 514


class TestProbeLogTarget:
    def test_returns_true_when_reachable(self):
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        with patch("decnet.logging.forwarder.socket.create_connection",
                   return_value=mock_conn):
            assert probe_log_target("192.168.1.5:5140") is True

    def test_returns_false_when_connection_refused(self):
        with patch("decnet.logging.forwarder.socket.create_connection",
                   side_effect=OSError("Connection refused")):
            assert probe_log_target("192.168.1.5:5140") is False

    def test_returns_false_on_timeout(self):
        with patch("decnet.logging.forwarder.socket.create_connection",
                   side_effect=TimeoutError("timed out")):
            assert probe_log_target("192.168.1.5:5140") is False

    def test_returns_false_on_invalid_target(self):
        # ValueError from parse_log_target is caught and returns False
        assert probe_log_target("not-a-valid-target") is False
