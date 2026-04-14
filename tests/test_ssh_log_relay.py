"""Tests for the SSH log relay that normalizes sshd/bash events."""

import os
import sys
import types
from pathlib import Path

import pytest

_SSH_TPL = str(Path(__file__).resolve().parent.parent / "templates" / "ssh")


def _load_relay():
    """Import log_relay with a real decnet_logging from the SSH template dir."""
    # Clear any stale stubs
    for mod_name in ("decnet_logging", "log_relay"):
        sys.modules.pop(mod_name, None)

    if _SSH_TPL not in sys.path:
        sys.path.insert(0, _SSH_TPL)

    import log_relay
    return log_relay


_relay = _load_relay()


def _capture(line: str) -> str | None:
    """Run _handle_line, collect output via monkey-patched write_syslog_file."""
    collected: list[str] = []
    original = _relay.write_syslog_file
    _relay.write_syslog_file = lambda s: collected.append(s)
    try:
        _relay._handle_line(line)
    finally:
        _relay.write_syslog_file = original
    return collected[0] if collected else None


class TestSshdAcceptedPassword:
    def test_accepted_password_emits_login_success(self):
        emitted = _capture(
            '<38>1 2026-04-14T05:48:12.611006+00:00 SRV-BRAVO-13 sshd 282 - -  Accepted password for root from 192.168.1.5 port 50854 ssh2'
        )
        assert emitted is not None
        assert "login_success" in emitted
        assert 'src_ip="192.168.1.5"' in emitted
        assert 'username="root"' in emitted
        assert 'auth_method="password"' in emitted

    def test_accepted_publickey(self):
        emitted = _capture(
            '<38>1 2026-04-14T05:48:12.611006+00:00 SRV-BRAVO-13 sshd 282 - -  Accepted publickey for admin from 10.0.0.1 port 12345 ssh2'
        )
        assert emitted is not None
        assert 'auth_method="publickey"' in emitted
        assert 'username="admin"' in emitted


class TestSshdSessionOpened:
    def test_session_opened(self):
        emitted = _capture(
            '<86>1 2026-04-14T05:48:12.611880+00:00 SRV-BRAVO-13 sshd 282 - -  pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)'
        )
        assert emitted is not None
        assert "session_opened" in emitted
        assert 'username="root"' in emitted


class TestSshdDisconnected:
    def test_disconnected(self):
        emitted = _capture(
            '<38>1 2026-04-14T05:54:50.710536+00:00 SRV-BRAVO-13 sshd 282 - -  Disconnected from user root 192.168.1.5 port 50854'
        )
        assert emitted is not None
        assert "disconnect" in emitted
        assert 'src_ip="192.168.1.5"' in emitted
        assert 'username="root"' in emitted


class TestSshdConnectionClosed:
    def test_connection_closed(self):
        emitted = _capture(
            '<38>1 2026-04-14T05:47:55.621236+00:00 SRV-BRAVO-13 sshd 280 - -  Connection closed by 192.168.1.5 port 52900 [preauth]'
        )
        assert emitted is not None
        assert "connection_closed" in emitted
        assert 'src_ip="192.168.1.5"' in emitted


class TestBashCommand:
    def test_bash_cmd(self):
        emitted = _capture(
            '<14>1 2026-04-14T05:48:12.628417+00:00 SRV-BRAVO-13 bash - - -  CMD uid=0 pwd=/root cmd=ls /var/www/html'
        )
        assert emitted is not None
        assert "command" in emitted
        assert 'command="ls /var/www/html"' in emitted

    def test_bash_cmd_with_pipes(self):
        emitted = _capture(
            '<14>1 2026-04-14T05:48:32.006502+00:00 SRV-BRAVO-13 bash - - -  CMD uid=0 pwd=/root cmd=cat /etc/passwd | grep root'
        )
        assert emitted is not None
        assert "cat /etc/passwd | grep root" in emitted


class TestUnmatchedLines:
    def test_pam_env_ignored(self):
        assert _capture('<83>1 2026-04-14T05:48:12.615198+00:00 SRV-BRAVO-13 sshd 282 - -  pam_env(sshd:session): Unable to open env file') is None

    def test_session_closed_ignored(self):
        assert _capture('<86>1 2026-04-14T05:54:50.710577+00:00 SRV-BRAVO-13 sshd 282 - -  pam_unix(sshd:session): session closed for user root') is None

    def test_syslogin_ignored(self):
        assert _capture('<38>1 2026-04-14T05:54:50.710307+00:00 SRV-BRAVO-13 sshd 282 - -  syslogin_perform_logout: logout() returned an error') is None
