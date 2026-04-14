"""
DECNET-PROBER standalone worker.

Runs as a detached host-level process. Probes targets on a configurable
interval and writes results as RFC 5424 syslog + JSON to the same log
files the collector uses. The ingester tails the JSON file and extracts
JARM bounties automatically.

Tech debt: writing directly to the collector's log files couples the
prober to the collector's file format. A future refactor should introduce
a shared log-sink abstraction.
"""

from __future__ import annotations

import asyncio
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from decnet.logging import get_logger
from decnet.prober.jarm import jarm_hash

logger = get_logger("prober")

# ─── RFC 5424 formatting (inline, mirrors templates/*/decnet_logging.py) ─────

_FACILITY_LOCAL0 = 16
_SD_ID = "decnet@55555"
_SEVERITY_INFO = 6
_SEVERITY_WARNING = 4

_MAX_HOSTNAME = 255
_MAX_APPNAME = 48
_MAX_MSGID = 32


def _sd_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _sd_element(fields: dict[str, Any]) -> str:
    if not fields:
        return "-"
    params = " ".join(f'{k}="{_sd_escape(str(v))}"' for k, v in fields.items())
    return f"[{_SD_ID} {params}]"


def _syslog_line(
    event_type: str,
    severity: int = _SEVERITY_INFO,
    msg: str | None = None,
    **fields: Any,
) -> str:
    pri = f"<{_FACILITY_LOCAL0 * 8 + severity}>"
    ts = datetime.now(timezone.utc).isoformat()
    hostname = "decnet-prober"
    appname = "prober"
    msgid = (event_type or "-")[:_MAX_MSGID]
    sd = _sd_element(fields)
    message = f" {msg}" if msg else ""
    return f"{pri}1 {ts} {hostname} {appname} - {msgid} {sd}{message}"


# ─── RFC 5424 parser (subset of collector's, for JSON generation) ─────────────

_RFC5424_RE = re.compile(
    r"^<\d+>1 "
    r"(\S+) "       # 1: TIMESTAMP
    r"(\S+) "       # 2: HOSTNAME
    r"(\S+) "       # 3: APP-NAME
    r"- "           # PROCID
    r"(\S+) "       # 4: MSGID (event_type)
    r"(.+)$",       # 5: SD + MSG
)
_SD_BLOCK_RE = re.compile(r'\[decnet@55555\s+(.*?)\]', re.DOTALL)
_PARAM_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
_IP_FIELDS = ("src_ip", "src", "client_ip", "remote_ip", "ip", "target_ip")


def _parse_to_json(line: str) -> dict[str, Any] | None:
    m = _RFC5424_RE.match(line)
    if not m:
        return None
    ts_raw, decky, service, event_type, sd_rest = m.groups()

    fields: dict[str, str] = {}
    msg = ""

    if sd_rest.startswith("["):
        block = _SD_BLOCK_RE.search(sd_rest)
        if block:
            for k, v in _PARAM_RE.findall(block.group(1)):
                fields[k] = v.replace('\\"', '"').replace("\\\\", "\\").replace("\\]", "]")
            msg_match = re.search(r'\]\s+(.+)$', sd_rest)
            if msg_match:
                msg = msg_match.group(1).strip()

    attacker_ip = "Unknown"
    for fname in _IP_FIELDS:
        if fname in fields:
            attacker_ip = fields[fname]
            break

    try:
        ts_formatted = datetime.fromisoformat(ts_raw).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        ts_formatted = ts_raw

    return {
        "timestamp": ts_formatted,
        "decky": decky,
        "service": service,
        "event_type": event_type,
        "attacker_ip": attacker_ip,
        "fields": fields,
        "msg": msg,
        "raw_line": line,
    }


# ─── Log writer ──────────────────────────────────────────────────────────────

def _write_event(
    log_path: Path,
    json_path: Path,
    event_type: str,
    severity: int = _SEVERITY_INFO,
    msg: str | None = None,
    **fields: Any,
) -> None:
    line = _syslog_line(event_type, severity=severity, msg=msg, **fields)

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()

    parsed = _parse_to_json(line)
    if parsed:
        with open(json_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(parsed) + "\n")
            f.flush()


# ─── Target parser ───────────────────────────────────────────────────────────

def _parse_targets(raw: str) -> list[tuple[str, int]]:
    """Parse 'ip:port,ip:port,...' into a list of (host, port) tuples."""
    targets: list[tuple[str, int]] = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            logger.warning("prober: skipping malformed target %r (missing port)", entry)
            continue
        host, _, port_str = entry.rpartition(":")
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError
            targets.append((host, port))
        except ValueError:
            logger.warning("prober: skipping malformed target %r (bad port)", entry)
    return targets


# ─── Probe cycle ─────────────────────────────────────────────────────────────

def _probe_cycle(
    targets: list[tuple[str, int]],
    log_path: Path,
    json_path: Path,
    timeout: float = 5.0,
) -> None:
    for host, port in targets:
        try:
            h = jarm_hash(host, port, timeout=timeout)
            _write_event(
                log_path, json_path,
                "jarm_fingerprint",
                target_ip=host,
                target_port=str(port),
                jarm_hash=h,
                msg=f"JARM {host}:{port} = {h}",
            )
            logger.info("prober: JARM %s:%d = %s", host, port, h)
        except Exception as exc:
            _write_event(
                log_path, json_path,
                "prober_error",
                severity=_SEVERITY_WARNING,
                target_ip=host,
                target_port=str(port),
                error=str(exc),
                msg=f"JARM probe failed for {host}:{port}: {exc}",
            )
            logger.warning("prober: JARM probe failed %s:%d: %s", host, port, exc)


# ─── Main worker ─────────────────────────────────────────────────────────────

async def prober_worker(
    log_file: str,
    targets_raw: str,
    interval: int = 300,
    timeout: float = 5.0,
) -> None:
    """
    Main entry point for the standalone prober process.

    Args:
        log_file: base path for log files (RFC 5424 to .log, JSON to .json)
        targets_raw: comma-separated ip:port pairs
        interval: seconds between probe cycles
        timeout: per-probe TCP timeout
    """
    targets = _parse_targets(targets_raw)
    if not targets:
        logger.error("prober: no valid targets, exiting")
        return

    log_path = Path(log_file)
    json_path = log_path.with_suffix(".json")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info("prober started targets=%d interval=%ds log=%s", len(targets), interval, log_path)

    _write_event(
        log_path, json_path,
        "prober_startup",
        target_count=str(len(targets)),
        interval=str(interval),
        msg=f"DECNET-PROBER started with {len(targets)} targets, interval {interval}s",
    )

    while True:
        await asyncio.to_thread(
            _probe_cycle, targets, log_path, json_path, timeout,
        )
        await asyncio.sleep(interval)
