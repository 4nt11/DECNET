"""
DECNET-PROBER standalone worker.

Runs as a detached host-level process. Discovers attacker IPs by tailing the
collector's JSON log file, then fingerprints them via multiple active probes:
- JARM (TLS server fingerprinting)
- HASSHServer (SSH server fingerprinting)
- TCP/IP stack fingerprinting (OS/tool identification)

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
from decnet.prober.hassh import hassh_server
from decnet.prober.jarm import JARM_EMPTY_HASH, jarm_hash
from decnet.prober.tcpfp import tcp_fingerprint
from decnet.telemetry import traced as _traced

logger = get_logger("prober")

# ─── Default ports per probe type ───────────────────────────────────────────

# JARM: common C2 callback / TLS server ports
DEFAULT_PROBE_PORTS: list[int] = [
    443, 8443, 8080, 4443, 50050, 2222, 993, 995, 8888, 9001,
]

# HASSHServer: common SSH server ports
DEFAULT_SSH_PORTS: list[int] = [22, 2222, 22222, 2022]

# TCP/IP stack: probe on ports commonly open on attacker machines.
# Wide spread gives the best chance of a SYN-ACK for TTL/fingerprint extraction.
DEFAULT_TCPFP_PORTS: list[int] = [22, 80, 443, 8080, 8443, 445, 3389]

# ─── RFC 5424 formatting (inline, mirrors templates/*/decnet_logging.py) ─────

_FACILITY_LOCAL0 = 16
_SD_ID = "relay@55555"
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
_SD_BLOCK_RE = re.compile(r'\[relay@55555\s+(.*?)\]', re.DOTALL)
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

@_traced("prober.discover_attackers")
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

@_traced("prober.probe_cycle")
def _probe_cycle(
    targets: set[str],
    probed: dict[str, dict[str, set[int]]],
    jarm_ports: list[int],
    ssh_ports: list[int],
    tcpfp_ports: list[int],
    log_path: Path,
    json_path: Path,
    timeout: float = 5.0,
) -> None:
    """
    Probe all known attacker IPs with JARM, HASSH, and TCP/IP fingerprinting.

    Args:
        targets: set of attacker IPs to probe
        probed: dict mapping IP -> {probe_type -> set of ports already probed}
        jarm_ports: TLS ports for JARM fingerprinting
        ssh_ports: SSH ports for HASSHServer fingerprinting
        tcpfp_ports: ports for TCP/IP stack fingerprinting
        log_path: RFC 5424 log file
        json_path: JSON log file
        timeout: per-probe TCP timeout
    """
    for ip in sorted(targets):
        ip_probed = probed.setdefault(ip, {})

        # Phase 1: JARM (TLS fingerprinting)
        _jarm_phase(ip, ip_probed, jarm_ports, log_path, json_path, timeout)

        # Phase 2: HASSHServer (SSH fingerprinting)
        _hassh_phase(ip, ip_probed, ssh_ports, log_path, json_path, timeout)

        # Phase 3: TCP/IP stack fingerprinting
        _tcpfp_phase(ip, ip_probed, tcpfp_ports, log_path, json_path, timeout)


@_traced("prober.jarm_phase")
def _jarm_phase(
    ip: str,
    ip_probed: dict[str, set[int]],
    ports: list[int],
    log_path: Path,
    json_path: Path,
    timeout: float,
) -> None:
    """JARM-fingerprint an IP on the given TLS ports."""
    done = ip_probed.setdefault("jarm", set())
    for port in ports:
        if port in done:
            continue
        try:
            h = jarm_hash(ip, port, timeout=timeout)
            done.add(port)
            if h == JARM_EMPTY_HASH:
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
        except Exception as exc:
            done.add(port)
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


@_traced("prober.hassh_phase")
def _hassh_phase(
    ip: str,
    ip_probed: dict[str, set[int]],
    ports: list[int],
    log_path: Path,
    json_path: Path,
    timeout: float,
) -> None:
    """HASSHServer-fingerprint an IP on the given SSH ports."""
    done = ip_probed.setdefault("hassh", set())
    for port in ports:
        if port in done:
            continue
        try:
            result = hassh_server(ip, port, timeout=timeout)
            done.add(port)
            if result is None:
                continue
            _write_event(
                log_path, json_path,
                "hassh_fingerprint",
                target_ip=ip,
                target_port=str(port),
                hassh_server_hash=result["hassh_server"],
                ssh_banner=result["banner"],
                kex_algorithms=result["kex_algorithms"],
                encryption_s2c=result["encryption_s2c"],
                mac_s2c=result["mac_s2c"],
                compression_s2c=result["compression_s2c"],
                msg=f"HASSH {ip}:{port} = {result['hassh_server']}",
            )
            logger.info("prober: HASSH %s:%d = %s", ip, port, result["hassh_server"])
        except Exception as exc:
            done.add(port)
            _write_event(
                log_path, json_path,
                "prober_error",
                severity=_SEVERITY_WARNING,
                target_ip=ip,
                target_port=str(port),
                error=str(exc),
                msg=f"HASSH probe failed for {ip}:{port}: {exc}",
            )
            logger.warning("prober: HASSH probe failed %s:%d: %s", ip, port, exc)


@_traced("prober.tcpfp_phase")
def _tcpfp_phase(
    ip: str,
    ip_probed: dict[str, set[int]],
    ports: list[int],
    log_path: Path,
    json_path: Path,
    timeout: float,
) -> None:
    """TCP/IP stack fingerprint an IP on the given ports."""
    done = ip_probed.setdefault("tcpfp", set())
    for port in ports:
        if port in done:
            continue
        try:
            result = tcp_fingerprint(ip, port, timeout=timeout)
            done.add(port)
            if result is None:
                continue
            _write_event(
                log_path, json_path,
                "tcpfp_fingerprint",
                target_ip=ip,
                target_port=str(port),
                tcpfp_hash=result["tcpfp_hash"],
                tcpfp_raw=result["tcpfp_raw"],
                ttl=str(result["ttl"]),
                window_size=str(result["window_size"]),
                df_bit=str(result["df_bit"]),
                mss=str(result["mss"]),
                window_scale=str(result["window_scale"]),
                sack_ok=str(result["sack_ok"]),
                timestamp=str(result["timestamp"]),
                options_order=result["options_order"],
                msg=f"TCPFP {ip}:{port} = {result['tcpfp_hash']}",
            )
            logger.info("prober: TCPFP %s:%d = %s", ip, port, result["tcpfp_hash"])
        except Exception as exc:
            done.add(port)
            _write_event(
                log_path, json_path,
                "prober_error",
                severity=_SEVERITY_WARNING,
                target_ip=ip,
                target_port=str(port),
                error=str(exc),
                msg=f"TCPFP probe failed for {ip}:{port}: {exc}",
            )
            logger.warning("prober: TCPFP probe failed %s:%d: %s", ip, port, exc)


# ─── Main worker ─────────────────────────────────────────────────────────────

@_traced("prober.worker")
async def prober_worker(
    log_file: str,
    interval: int = 300,
    timeout: float = 5.0,
    ports: list[int] | None = None,
    ssh_ports: list[int] | None = None,
    tcpfp_ports: list[int] | None = None,
) -> None:
    """
    Main entry point for the standalone prober process.

    Discovers attacker IPs automatically by tailing the JSON log file,
    then fingerprints each IP via JARM, HASSH, and TCP/IP stack probes.

    Args:
        log_file: base path for log files (RFC 5424 to .log, JSON to .json)
        interval: seconds between probe cycles
        timeout: per-probe TCP timeout
        ports: JARM TLS ports (defaults to DEFAULT_PROBE_PORTS)
        ssh_ports: HASSH SSH ports (defaults to DEFAULT_SSH_PORTS)
        tcpfp_ports: TCP fingerprint ports (defaults to DEFAULT_TCPFP_PORTS)
    """
    jarm_ports = ports or DEFAULT_PROBE_PORTS
    hassh_ports = ssh_ports or DEFAULT_SSH_PORTS
    tcp_ports = tcpfp_ports or DEFAULT_TCPFP_PORTS

    all_ports_str = (
        f"jarm={','.join(str(p) for p in jarm_ports)} "
        f"ssh={','.join(str(p) for p in hassh_ports)} "
        f"tcpfp={','.join(str(p) for p in tcp_ports)}"
    )

    log_path = Path(log_file)
    json_path = log_path.with_suffix(".json")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.info(
        "prober started interval=%ds %s log=%s",
        interval, all_ports_str, log_path,
    )

    _write_event(
        log_path, json_path,
        "prober_startup",
        interval=str(interval),
        probe_ports=all_ports_str,
        msg=f"DECNET-PROBER started, interval {interval}s, {all_ports_str}",
    )

    known_attackers: set[str] = set()
    probed: dict[str, dict[str, set[int]]] = {}  # IP -> {type -> ports}
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
                _probe_cycle, known_attackers, probed,
                jarm_ports, hassh_ports, tcp_ports,
                log_path, json_path, timeout,
            )

        await asyncio.sleep(interval)
