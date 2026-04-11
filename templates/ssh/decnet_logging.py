#!/usr/bin/env python3
"""
Shared RFC 5424 syslog helper for DECNET service templates.

Provides two functions consumed by every service's server.py:
  - syslog_line(service, hostname, event_type, severity, **fields) -> str
  - write_syslog_file(line: str) -> None
  - forward_syslog(line: str, log_target: str) -> None

RFC 5424 structure:
  <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ELEMENT] MSG

Facility: local0 (16), PEN for SD element ID: decnet@55555
"""

import logging
import logging.handlers
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ─── Constants ────────────────────────────────────────────────────────────────

_FACILITY_LOCAL0 = 16
_SD_ID = "decnet@55555"
_NILVALUE = "-"

SEVERITY_EMERG   = 0
SEVERITY_ALERT   = 1
SEVERITY_CRIT    = 2
SEVERITY_ERROR   = 3
SEVERITY_WARNING = 4
SEVERITY_NOTICE  = 5
SEVERITY_INFO    = 6
SEVERITY_DEBUG   = 7

_MAX_HOSTNAME = 255
_MAX_APPNAME  = 48
_MAX_MSGID    = 32

_LOG_FILE_ENV     = "DECNET_LOG_FILE"
_DEFAULT_LOG_FILE = "/var/log/decnet/decnet.log"
_MAX_BYTES        = 10 * 1024 * 1024  # 10 MB
_BACKUP_COUNT     = 5

# ─── Formatter ────────────────────────────────────────────────────────────────

def _sd_escape(value: str) -> str:
    """Escape SD-PARAM-VALUE per RFC 5424 §6.3.3."""
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
    timestamp: datetime | None = None,
    msg: str | None = None,
    **fields: Any,
) -> str:
    """
    Return a single RFC 5424-compliant syslog line (no trailing newline).

    Args:
        service:    APP-NAME (e.g. "http", "mysql")
        hostname:   HOSTNAME (decky node name)
        event_type: MSGID    (e.g. "request", "login_attempt")
        severity:   Syslog severity integer (default: INFO=6)
        timestamp:  UTC datetime; defaults to now
        msg:        Optional free-text MSG
        **fields:   Encoded as structured data params
    """
    pri     = f"<{_FACILITY_LOCAL0 * 8 + severity}>"
    ts      = (timestamp or datetime.now(timezone.utc)).isoformat()
    host    = (hostname or _NILVALUE)[:_MAX_HOSTNAME]
    appname = (service  or _NILVALUE)[:_MAX_APPNAME]
    msgid   = (event_type or _NILVALUE)[:_MAX_MSGID]
    sd      = _sd_element(fields)
    message = f" {msg}" if msg else ""
    return f"{pri}1 {ts} {host} {appname} {_NILVALUE} {msgid} {sd}{message}"


# ─── File handler ─────────────────────────────────────────────────────────────

_file_logger: logging.Logger | None = None


def _get_file_logger() -> logging.Logger:
    global _file_logger
    if _file_logger is not None:
        return _file_logger

    log_path = Path(os.environ.get(_LOG_FILE_ENV, _DEFAULT_LOG_FILE))
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
    except OSError:
        handler = logging.StreamHandler()

    handler.setFormatter(logging.Formatter("%(message)s"))
    _file_logger = logging.getLogger("decnet.syslog")
    _file_logger.setLevel(logging.DEBUG)
    _file_logger.propagate = False
    _file_logger.addHandler(handler)
    return _file_logger



_json_logger: logging.Logger | None = None

def _get_json_logger() -> logging.Logger:
    global _json_logger
    if _json_logger is not None:
        return _json_logger

    log_path_str = os.environ.get(_LOG_FILE_ENV, _DEFAULT_LOG_FILE)
    json_path = Path(log_path_str).with_suffix(".json")
    try:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            json_path,
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
    except OSError:
        handler = logging.StreamHandler()

    handler.setFormatter(logging.Formatter("%(message)s"))
    _json_logger = logging.getLogger("decnet.json")
    _json_logger.setLevel(logging.DEBUG)
    _json_logger.propagate = False
    _json_logger.addHandler(handler)
    return _json_logger




def write_syslog_file(line: str) -> None:
    """Append a syslog line to the rotating log file."""
    try:
        _get_file_logger().info(line)
        
        # Also parse and write JSON log
        import json
        import re
        from datetime import datetime
        from typing import Optional, Any
        
        _RFC5424_RE: re.Pattern = re.compile(
            r"^<\d+>1 "
            r"(\S+) "       # 1: TIMESTAMP
            r"(\S+) "       # 2: HOSTNAME (decky name)
            r"(\S+) "       # 3: APP-NAME (service)
            r"- "           # PROCID always NILVALUE
            r"(\S+) "       # 4: MSGID (event_type)
            r"(.+)$",       # 5: SD element + optional MSG
        )
        _SD_BLOCK_RE: re.Pattern = re.compile(r'\[decnet@55555\s+(.*?)\]', re.DOTALL)
        _PARAM_RE: re.Pattern = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
        _IP_FIELDS: tuple[str, ...] = ("src_ip", "src", "client_ip", "remote_ip", "ip")
        
        _m: Optional[re.Match] = _RFC5424_RE.match(line)
        if _m:
            _ts_raw: str
            _decky: str
            _service: str
            _event_type: str
            _sd_rest: str
            _ts_raw, _decky, _service, _event_type, _sd_rest = _m.groups()
            
            _fields: dict[str, str] = {}
            _msg: str = ""
            
            if _sd_rest.startswith("-"):
                _msg = _sd_rest[1:].lstrip()
            elif _sd_rest.startswith("["):
                _block: Optional[re.Match] = _SD_BLOCK_RE.search(_sd_rest)
                if _block:
                    for _k, _v in _PARAM_RE.findall(_block.group(1)):
                        _fields[_k] = _v.replace('\\"', '"').replace("\\\\", "\\").replace("\\]", "]")
                    
                    # extract msg after the block
                    _msg_match: Optional[re.Match] = re.search(r'\]\s+(.+)$', _sd_rest)
                    if _msg_match:
                        _msg = _msg_match.group(1).strip()
            else:
                _msg = _sd_rest
                    
            _attacker_ip: str = "Unknown"
            for _fname in _IP_FIELDS:
                if _fname in _fields:
                    _attacker_ip = _fields[_fname]
                    break
                    
            # Parse timestamp to normalize it
            _ts_formatted: str
            try:
                _ts_formatted = datetime.fromisoformat(_ts_raw).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                _ts_formatted = _ts_raw
                
            _payload: dict[str, Any] = {
                "timestamp": _ts_formatted,
                "decky": _decky,
                "service": _service,
                "event_type": _event_type,
                "attacker_ip": _attacker_ip,
                "fields": json.dumps(_fields),
                "msg": _msg,
                "raw_line": line
            }
            _get_json_logger().info(json.dumps(_payload))
            
    except Exception:
        pass


# ─── TCP forwarding ───────────────────────────────────────────────────────────

def forward_syslog(line: str, log_target: str) -> None:
    """Forward a syslog line over TCP to log_target (ip:port)."""
    if not log_target:
        return
    try:
        host, port = log_target.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=3) as s:
            s.sendall((line + "\n").encode())
    except Exception:
        pass
