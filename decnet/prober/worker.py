"""
DECNET-PROBER standalone worker.

Runs as a detached host-level process. Discovers attacker IPs by tailing the
collector's JSON log file, then JARM-probes them on common C2/TLS ports.
Results are written as RFC 5424 syslog + JSON to the same log files.

Target discovery is fully automatic — every unique attacker IP seen in the
log stream gets probed. No manual target list required.

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
from decnet.prober.jarm import JARM_EMPTY_HASH, jarm_hash

logger = get_logger("prober")

# ─── Default ports to JARM-probe on each attacker IP ─────────────────────────
# Common C2 callback / TLS server ports (Cobalt Strike, Sliver, Metasploit, etc.)

DEFAULT_PROBE_PORTS: list[int] = [
    443, 8443, 8080, 4443, 50050, 2222, 993, 995, 8888, 9001,
]

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


# ─── Target discovery from log stream ────────────────────────────────────────

def _discover_attackers(json_path: Path, position: int) -> tuple[set[str], int]:
    """
    Read new JSON log lines from the given position and extract unique
    attacker IPs. Returns (new_ips, new_position).

    Only considers IPs that are not "Unknown" and come from events that
    indicate real attacker interaction (not prober's own events).
    """
    new_ips: set[str] = set()

    if not json_path.exists():
        return new_ips, position

    size = json_path.stat().st_size
    if size < position:
        position = 0  # file rotated

    if size == position:
        return new_ips, position

    with open(json_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(position)
        while True:
            line = f.readline()
            if not line:
                break
            if not line.endswith("\n"):
                break  # partial line

            try:
                record = json.loads(line.strip())
            except json.JSONDecodeError:
                position = f.tell()
                continue

            # Skip our own events
            if record.get("service") == "prober":
                position = f.tell()
                continue

            ip = record.get("attacker_ip", "Unknown")
            if ip != "Unknown" and ip:
                new_ips.add(ip)

            position = f.tell()

    return new_ips, position


# ─── Probe cycle ─────────────────────────────────────────────────────────────

def _probe_cycle(
    targets: set[str],
    probed: dict[str, set[int]],
    ports: list[int],
    log_path: Path,
    json_path: Path,
    timeout: float = 5.0,
) -> None:
    """
    Probe all known attacker IPs on the configured ports.

    Args:
        targets: set of attacker IPs to probe
        probed: dict mapping IP -> set of ports already successfully probed
        ports: list of ports to probe on each IP
        log_path: RFC 5424 log file
        json_path: JSON log file
        timeout: per-probe TCP timeout
    """
    for ip in sorted(targets):
        already_done = probed.get(ip, set())
        ports_to_probe = [p for p in ports if p not in already_done]

        if not ports_to_probe:
            continue

        for port in ports_to_probe:
            try:
                h = jarm_hash(ip, port, timeout=timeout)
                if h == JARM_EMPTY_HASH:
                    # No TLS server on this port — don't log, don't reprobed
                    probed.setdefault(ip, set()).add(port)
                    continue

                _write_event(
                    log_path, json_path,
                    "jarm_fingerprint",
                    target_ip=ip,
                    target_port=str(port),
                    jarm_hash=h,
                    msg=f"JARM {ip}:{port} = {h}",
                )
                logger.info("prober: JARM %s:%d = %s", ip, port, h)
                probed.setdefault(ip, set()).add(port)

            except Exception as exc:
                _write_event(
                    log_path, json_path,
                    "prober_error",
                    severity=_SEVERITY_WARNING,
                    target_ip=ip,
                    target_port=str(port),
                    error=str(exc),
                    msg=f"JARM probe failed for {ip}:{port}: {exc}",
                )
                logger.warning("prober: JARM probe failed %s:%d: %s", ip, port, exc)
                # Mark as probed to avoid infinite retries
                probed.setdefault(ip, set()).add(port)


# ─── Main worker ─────────────────────────────────────────────────────────────

async def prober_worker(
    log_file: str,
    interval: int = 300,
    timeout: float = 5.0,
    ports: list[int] | None = None,
) -> None:
    """
    Main entry point for the standalone prober process.

    Discovers attacker IPs automatically by tailing the JSON log file,
    then JARM-probes each IP on common C2 ports.

    Args:
        log_file: base path for log files (RFC 5424 to .log, JSON to .json)
        interval: seconds between probe cycles
        timeout: per-probe TCP timeout
        ports: list of ports to probe (defaults to DEFAULT_PROBE_PORTS)
    """
    probe_ports = ports or DEFAULT_PROBE_PORTS

    log_path = Path(log_file)
    json_path = log_path.with_suffix(".json")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(
        "prober started interval=%ds ports=%s log=%s",
        interval, ",".join(str(p) for p in probe_ports), log_path,
    )

    _write_event(
        log_path, json_path,
        "prober_startup",
        interval=str(interval),
        probe_ports=",".join(str(p) for p in probe_ports),
        msg=f"DECNET-PROBER started, interval {interval}s, "
            f"ports {','.join(str(p) for p in probe_ports)}",
    )

    known_attackers: set[str] = set()
    probed: dict[str, set[int]] = {}  # IP -> set of ports already probed
    log_position: int = 0

    while True:
        # Discover new attacker IPs from the log stream
        new_ips, log_position = await asyncio.to_thread(
            _discover_attackers, json_path, log_position,
        )

        if new_ips - known_attackers:
            fresh = new_ips - known_attackers
            known_attackers.update(fresh)
            logger.info(
                "prober: discovered %d new attacker(s), total=%d",
                len(fresh), len(known_attackers),
            )

        if known_attackers:
            await asyncio.to_thread(
                _probe_cycle, known_attackers, probed, probe_ports,
                log_path, json_path, timeout,
            )

        await asyncio.sleep(interval)
