"""
RFC 5424 syslog formatting and log-file writing for the fleet sniffer.

Reuses the same wire format as templates/sniffer/decnet_logging.py so the
existing collector parser and ingester can consume events without changes.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from decnet.collector.worker import parse_rfc5424
from decnet.telemetry import traced as _traced

# ─── Constants (must match templates/sniffer/decnet_logging.py) ──────────────

_FACILITY_LOCAL0 = 16
_SD_ID = "decnet@55555"
_NILVALUE = "-"

SEVERITY_INFO = 6
SEVERITY_WARNING = 4

_MAX_HOSTNAME = 255
_MAX_APPNAME = 48
_MAX_MSGID = 32


# ─── Formatter ───────────────────────────────────────────────────────────────

def _sd_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _sd_element(fields: dict[str, Any]) -> str:
    if not fields:
        return _NILVALUE
    params = " ".join(f'{k}="{_sd_escape(str(v))}"' for k, v in fields.items())
    return f"[{_SD_ID} {params}]"


def syslog_line(
    service: str,
    hostname: str,
    event_type: str,
    severity: int = SEVERITY_INFO,
    msg: str | None = None,
    **fields: Any,
) -> str:
    pri = f"<{_FACILITY_LOCAL0 * 8 + severity}>"
    ts = datetime.now(timezone.utc).isoformat()
    host = (hostname or _NILVALUE)[:_MAX_HOSTNAME]
    appname = (service or _NILVALUE)[:_MAX_APPNAME]
    msgid = (event_type or _NILVALUE)[:_MAX_MSGID]
    sd = _sd_element(fields)
    message = f" {msg}" if msg else ""
    return f"{pri}1 {ts} {host} {appname} {_NILVALUE} {msgid} {sd}{message}"


@_traced("sniffer.write_event")
def write_event(line: str, log_path: Path, json_path: Path) -> None:
    """Append a syslog line to the raw log and its parsed JSON to the json log."""
    with open(log_path, "a", encoding="utf-8") as lf:
        lf.write(line + "\n")
        lf.flush()
    parsed = parse_rfc5424(line)
    if parsed:
        with open(json_path, "a", encoding="utf-8") as jf:
            jf.write(json.dumps(parsed) + "\n")
            jf.flush()
