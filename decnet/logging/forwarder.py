# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Log forwarding helpers.

DECNET is agnostic to what receives logs — any TCP/UDP listener works
(Logstash, Splunk, Graylog, netcat, etc.).

Each service plugin handles the actual forwarding by injecting the
LOG_TARGET environment variable into its container. This module provides
shared utilities for validating and parsing the log_target string.
"""

import socket

from decnet.telemetry import traced as _traced


def parse_log_target(log_target: str) -> tuple[str, int]:
    """
    Parse "ip:port" into (host, port).
    Raises ValueError on bad format.
    """
    parts = log_target.rsplit(":", 1)
    if len(parts) != 2 or not parts[1].isdigit():
        raise ValueError(f"Invalid log_target '{log_target}'. Expected format: ip:port")
    return parts[0], int(parts[1])


@_traced("logging.probe_log_target")
def probe_log_target(log_target: str, timeout: float = 2.0) -> bool:
    """
    Return True if the log target is reachable (TCP connect succeeds).
    Non-fatal — just used to warn the user before deployment.
    """
    try:
        host, port = parse_log_target(log_target)
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False
