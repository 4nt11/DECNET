#!/usr/bin/env python3
"""
SSH log relay — reads rsyslog output from the named pipe and re-emits
matched sshd/bash events as proper DECNET RFC 5424 syslog lines to stdout.

Matched events:
  - Accepted password (login_success)
  - Connection closed (connection_closed)
  - Disconnected from user (disconnect)
  - Session opened (session_opened)
  - bash CMD (command)
"""

import os
import re
import sys

from decnet_logging import syslog_line, write_syslog_file, SEVERITY_INFO, SEVERITY_WARNING

NODE_NAME = os.environ.get("NODE_NAME", "ssh-decky")
SERVICE = "ssh"

# sshd patterns
_ACCEPTED_RE = re.compile(
    r"Accepted (\S+) for (\S+) from (\S+) port (\d+)"
)
_SESSION_RE = re.compile(
    r"session opened for user (\S+?)(?:\(uid=\d+\))? by"
)
_DISCONNECTED_RE = re.compile(
    r"Disconnected from user (\S+) (\S+) port (\d+)"
)
_CONN_CLOSED_RE = re.compile(
    r"Connection closed by (\S+) port (\d+)"
)

# bash PROMPT_COMMAND pattern
_BASH_CMD_RE = re.compile(
    r"CMD\s+uid=(\S+)\s+pwd=(\S+)\s+cmd=(.*)"
)


def _handle_line(line: str) -> None:
    """Parse a raw rsyslog line and emit a DECNET syslog line if it matches."""

    # --- Accepted password ---
    m = _ACCEPTED_RE.search(line)
    if m:
        method, user, src_ip, port = m.groups()
        write_syslog_file(syslog_line(
            SERVICE, NODE_NAME, "login_success", SEVERITY_WARNING,
            src_ip=src_ip, username=user, auth_method=method, src_port=port,
        ))
        return

    # --- Session opened ---
    m = _SESSION_RE.search(line)
    if m:
        user = m.group(1)
        write_syslog_file(syslog_line(
            SERVICE, NODE_NAME, "session_opened", SEVERITY_INFO,
            username=user,
        ))
        return

    # --- Disconnected from user ---
    m = _DISCONNECTED_RE.search(line)
    if m:
        user, src_ip, port = m.groups()
        write_syslog_file(syslog_line(
            SERVICE, NODE_NAME, "disconnect", SEVERITY_INFO,
            src_ip=src_ip, username=user, src_port=port,
        ))
        return

    # --- Connection closed ---
    m = _CONN_CLOSED_RE.search(line)
    if m:
        src_ip, port = m.groups()
        write_syslog_file(syslog_line(
            SERVICE, NODE_NAME, "connection_closed", SEVERITY_INFO,
            src_ip=src_ip, src_port=port,
        ))
        return

    # --- bash CMD ---
    m = _BASH_CMD_RE.search(line)
    if m:
        uid, pwd, cmd = m.groups()
        write_syslog_file(syslog_line(
            SERVICE, NODE_NAME, "command", SEVERITY_INFO,
            uid=uid, pwd=pwd, command=cmd,
        ))
        return


def main() -> None:
    pipe_path = "/var/run/decnet-logs"
    while True:
        with open(pipe_path, "r") as pipe:
            for line in pipe:
                _handle_line(line.rstrip("\n"))


if __name__ == "__main__":
    main()
