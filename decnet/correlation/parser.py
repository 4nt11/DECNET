"""
RFC 5424 log line parser for the DECNET correlation engine.

Parses log lines produced by decnet service containers and extracts
the fields needed for cross-decky correlation: attacker IP, decky name,
service, event type, and timestamp.

Log format (produced by decnet.logging.syslog_formatter):
  <PRI>1 TIMESTAMP HOSTNAME APP-NAME - MSGID [relay@55555 k1="v1" k2="v2"] [MSG]

The attacker IP may appear under several field names depending on service:
  src_ip  — ftp, smtp, http, most services
  src     — mssql (legacy)
  client_ip, remote_ip, ip  — future / third-party services
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

# RFC 5424 line structure
_RFC5424_RE = re.compile(
    r"^<\d+>1 "
    r"(\S+) "       # 1: TIMESTAMP
    r"(\S+) "       # 2: HOSTNAME (decky name)
    r"(\S+) "       # 3: APP-NAME (service)
    r"- "           # PROCID always NILVALUE
    r"(\S+) "       # 4: MSGID (event_type)
    r"(.+)$",       # 5: SD element + optional MSG
)

# Structured data block: [relay@55555 k="v" ...]
_SD_BLOCK_RE = re.compile(r'\[relay@55555\s+(.*?)\]', re.DOTALL)

# Individual param: key="value" (with escaped chars inside value)
_PARAM_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

# Field names to probe for attacker IP, in priority order
_IP_FIELDS = ("src_ip", "src", "client_ip", "remote_ip", "remote_addr", "target_ip", "ip")


@dataclass
class LogEvent:
    """A single parsed event from a DECNET syslog line."""

    timestamp: datetime
    decky: str          # HOSTNAME field — the decky node name
    service: str        # APP-NAME — which honeypot service
    event_type: str     # MSGID — what happened (connection, login_attempt, …)
    attacker_ip: str | None  # extracted from SD params; None if not present
    fields: dict[str, str]   # all structured data params
    raw: str            # original log line (stripped)


def _parse_sd_params(sd_rest: str) -> dict[str, str]:
    """Extract key=value pairs from the SD element portion of a log line."""
    block = _SD_BLOCK_RE.search(sd_rest)
    if not block:
        return {}
    params: dict[str, str] = {}
    for key, val in _PARAM_RE.findall(block.group(1)):
        # Unescape RFC 5424 SD-PARAM-VALUE escapes
        params[key] = val.replace('\\"', '"').replace("\\\\", "\\").replace("\\]", "]")
    return params


def _extract_attacker_ip(fields: dict[str, str]) -> str | None:
    for fname in _IP_FIELDS:
        if fname in fields:
            return fields[fname]
    return None


def parse_line(line: str) -> LogEvent | None:
    """
    Parse a single RFC 5424 DECNET syslog line into a LogEvent.

    Returns None for blank lines, non-DECNET lines, or lines missing
    the required RFC 5424 header fields.
    """
    line = line.strip()
    if not line:
        return None

    m = _RFC5424_RE.match(line)
    if not m:
        return None

    ts_raw, decky, service, event_type, sd_rest = m.groups()

    if decky == "-" or service == "-":
        return None

    try:
        timestamp = datetime.fromisoformat(ts_raw)
    except ValueError:
        return None

    fields = _parse_sd_params(sd_rest)
    attacker_ip = _extract_attacker_ip(fields)

    return LogEvent(
        timestamp=timestamp,
        decky=decky,
        service=service,
        event_type=event_type,
        attacker_ip=attacker_ip,
        fields=fields,
        raw=line,
    )
