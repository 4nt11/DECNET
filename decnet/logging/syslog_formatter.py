from __future__ import annotations
"""
RFC 5424 syslog formatter for DECNET.

Produces fully-compliant syslog messages:
  <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ELEMENT] MSG

Facility: local0 (16)
PEN for structured data: decnet@55555
"""

from datetime import datetime, timezone
from typing import Any


FACILITY_LOCAL0 = 16
NILVALUE = "-"
_SD_ID = "decnet@55555"

SEVERITY_INFO    = 6
SEVERITY_WARNING = 4
SEVERITY_ERROR   = 3

# RFC 5424 field length limits
_MAX_HOSTNAME = 255
_MAX_APPNAME  = 48
_MAX_MSGID    = 32


def _pri(severity: int) -> str:
    return f"<{FACILITY_LOCAL0 * 8 + severity}>"


def _truncate(value: str, maxlen: int) -> str:
    return value[:maxlen] if len(value) > maxlen else value


def _sd_escape(value: str) -> str:
    """Escape SD-PARAM-VALUE per RFC 5424 §6.3.3."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _sd_element(fields: dict[str, Any]) -> str:
    if not fields:
        return NILVALUE
    params = " ".join(
        f'{k}="{_sd_escape(str(v))}"'
        for k, v in fields.items()
    )
    return f"[{_SD_ID} {params}]"


def format_rfc5424(
    service: str,
    hostname: str,
    event_type: str,
    severity: int = SEVERITY_INFO,
    timestamp: datetime | None = None,
    msg: str | None = None,
    **fields: Any,
) -> str:
    """
    Return a single RFC 5424-compliant syslog line (no trailing newline).

    Args:
        service:    APP-NAME field (e.g. "http", "mysql")
        hostname:   HOSTNAME field (the decky node name)
        event_type: MSGID field (e.g. "request", "login_attempt")
        severity:   Syslog severity integer (default: INFO=6)
        timestamp:  Datetime to use; defaults to utcnow
        msg:        Optional free-text MSG suffix
        **fields:   Arbitrary key=value pairs encoded in structured data
    """
    ts = (timestamp or datetime.now(timezone.utc)).isoformat()

    pri       = _pri(severity)
    version   = "1"
    host      = _truncate(hostname or NILVALUE, _MAX_HOSTNAME)
    appname   = _truncate(service or NILVALUE, _MAX_APPNAME)
    procid    = NILVALUE
    msgid     = _truncate(event_type or NILVALUE, _MAX_MSGID)
    sd        = _sd_element(fields)
    message   = f" {msg}" if msg else ""

    return f"{pri}{version} {ts} {host} {appname} {procid} {msgid} {sd}{message}"
