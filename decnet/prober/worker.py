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
import contextlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from sqlalchemy.engine import Engine
from sqlmodel import Session

from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    make_thread_safe_publisher,
    run_control_listener,
    run_health_heartbeat,
)
from decnet.correlation.fingerprint_rotation import (
    ProbeType,
    record_fingerprint,
)
from decnet.logging import get_logger
from decnet.prober.hassh import hassh_server
from decnet.prober.jarm import JARM_EMPTY_HASH, jarm_hash
from decnet.prober.tcpfp import tcp_fingerprint
from decnet.prober.tlscert import fetch_leaf_cert
from decnet.telemetry import traced as _traced

logger = get_logger("prober")


def _build_sync_engine() -> Engine:
    """Construct a sync SQLite engine for rotation-detection state.

    Used inline by the prober; it lives outside the async repository
    layer because rotation detection is a sync hook on a sync probe
    path.  Honors the same defaulting as
    ``decnet.web.db.sqlite.repository.SQLiteRepository``.
    """
    import os
    from decnet.config import _ROOT
    from decnet.web.db.sqlite.database import get_sync_engine
    db_path = os.environ.get("DECNET_DB_PATH", str(_ROOT / "decnet.db"))
    return get_sync_engine(db_path)

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

ProbePublishFn = Callable[[str, dict[str, Any]], None]

# Rotation recorder: takes (attacker_ip, port, probe_type, new_hash) and
# performs the rotation-detection upsert + derived-event emission for the
# DEBT-032 substrate-fingerprint flow.  Optional; when None the prober
# behaves exactly as before (raw fingerprint emit only, no rotation
# detection).  Construction lives at worker startup so phase functions
# don't have to know about the DB engine.
RotationRecorderFn = Callable[[str, int, "ProbeType", str], None]


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
    publish_fn: ProbePublishFn | None = None,
    record_rotation: RotationRecorderFn | None = None,
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
        _jarm_phase(ip, ip_probed, jarm_ports, log_path, json_path, timeout, publish_fn, record_rotation)

        # Phase 2: HASSHServer (SSH fingerprinting)
        _hassh_phase(ip, ip_probed, ssh_ports, log_path, json_path, timeout, publish_fn, record_rotation)

        # Phase 3: TCP/IP stack fingerprinting
        _tcpfp_phase(ip, ip_probed, tcpfp_ports, log_path, json_path, timeout, publish_fn, record_rotation)

        # Phase 4: IPv6 link-local leak (active ICMPv6 solicitation; on-link only)
        _ipv6_leak_phase(ip, ip_probed, log_path, json_path, timeout, publish_fn)


@_traced("prober.jarm_phase")
def _jarm_phase(
    ip: str,
    ip_probed: dict[str, set[int]],
    ports: list[int],
    log_path: Path,
    json_path: Path,
    timeout: float,
    publish_fn: ProbePublishFn | None = None,
    record_rotation: RotationRecorderFn | None = None,
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
            if record_rotation is not None:
                record_rotation(ip, port, "jarm", h)
            if publish_fn is not None:
                publish_fn(
                    "jarm",
                    {"attacker_ip": ip, "port": port, "jarm_hash": h},
                )
            # Cert capture: a non-empty JARM hash proves the port speaks
            # TLS, so a follow-up real handshake is worth attempting.
            # Failures are silent — the next probe target must not stall.
            _capture_tls_cert(ip, port, log_path, json_path, timeout, publish_fn)
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


@_traced("prober.tls_cert_capture")
def _capture_tls_cert(
    ip: str,
    port: int,
    log_path: Path,
    json_path: Path,
    timeout: float,
    publish_fn: ProbePublishFn | None,
) -> None:
    """Fetch the leaf TLS cert from ``ip:port`` and emit a tls_certificate
    event. No-op when the handshake fails (silent — JARM already proved
    the port responds, but the real handshake can still fail for many
    reasons: cipher mismatch, SNI gating, mTLS requirement)."""
    try:
        cert = fetch_leaf_cert(ip, port, timeout=timeout)
    except Exception as exc:
        # fetch_leaf_cert is supposed to swallow errors; defense in depth.
        logger.warning("prober: TLS cert fetch crashed %s:%d: %s", ip, port, exc)
        return
    if cert is None:
        return

    sans_csv = ",".join(cert["sans"])
    _write_event(
        log_path, json_path,
        "tls_certificate",
        target_ip=ip,
        target_port=str(port),
        subject_cn=cert["subject_cn"],
        issuer=cert["issuer"],
        self_signed=str(cert["self_signed"]).lower(),
        not_before=cert["not_before"],
        not_after=cert["not_after"],
        sans=sans_csv,
        cert_sha256=cert["cert_sha256"],
        msg=f"TLS cert {ip}:{port} CN={cert['subject_cn']} sha256={cert['cert_sha256'][:16]}...",
    )
    logger.info(
        "prober: TLS cert %s:%d CN=%s sha256=%s",
        ip, port, cert["subject_cn"], cert["cert_sha256"],
    )
    if publish_fn is not None:
        publish_fn(
            "tls_certificate",
            {
                "attacker_ip": ip,
                "port": port,
                "subject_cn": cert["subject_cn"],
                "cert_sha256": cert["cert_sha256"],
                "self_signed": cert["self_signed"],
            },
        )


@_traced("prober.hassh_phase")
def _hassh_phase(
    ip: str,
    ip_probed: dict[str, set[int]],
    ports: list[int],
    log_path: Path,
    json_path: Path,
    timeout: float,
    publish_fn: ProbePublishFn | None = None,
    record_rotation: RotationRecorderFn | None = None,
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
            if record_rotation is not None:
                record_rotation(ip, port, "hassh", result["hassh_server"])
            if publish_fn is not None:
                publish_fn(
                    "hassh",
                    {
                        "attacker_ip": ip,
                        "port": port,
                        "hassh_server": result["hassh_server"],
                        "ssh_banner": result["banner"],
                    },
                )
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
    publish_fn: ProbePublishFn | None = None,
    record_rotation: RotationRecorderFn | None = None,
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
                tos=str(result["tos"]),
                dscp=str(result["dscp"]),
                ecn=str(result["ecn"]),
                server_isn=str(result["server_isn"]),
                msg=f"TCPFP {ip}:{port} = {result['tcpfp_hash']}",
            )
            logger.info("prober: TCPFP %s:%d = %s", ip, port, result["tcpfp_hash"])
            if record_rotation is not None:
                record_rotation(ip, port, "tcpfp", result["tcpfp_hash"])
            if publish_fn is not None:
                publish_fn(
                    "tcpfp",
                    {
                        "attacker_ip": ip,
                        "port": port,
                        "tcpfp_hash": result["tcpfp_hash"],
                        "ttl": result["ttl"],
                        "mss": result["mss"],
                    },
                )
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


@_traced("prober.ipv6_leak_phase")
def _ipv6_leak_phase(
    ip: str,
    ip_probed: dict[str, set[int]],
    log_path: Path,
    json_path: Path,
    timeout: float,
    publish_fn: ProbePublishFn | None = None,
) -> None:
    """Attempt active ICMPv6 solicitation to elicit a fe80:: response.

    Skipped when:
    - already attempted for this attacker in this cycle
    - attacker is not on a directly connected (link-local reachable) L2
    - scapy unavailable or the local iface has no fe80:: address
    """
    done = ip_probed.setdefault("ipv6_leak", set())
    # Use port 0 as a sentinel (no port concept for ICMPv6 probes).
    if 0 in done:
        return
    done.add(0)

    from decnet.prober.ipv6_leak import _is_on_link, _resolve_iface_for_ip, solicit_ipv6_leak

    if not _is_on_link(ip):
        logger.debug("prober: ipv6_leak: %s is not on-link — skip active probe", ip)
        return

    iface = _resolve_iface_for_ip(ip)
    if iface is None:
        logger.debug("prober: ipv6_leak: cannot determine iface for %s", ip)
        return

    try:
        evidence = solicit_ipv6_leak(ip, iface, timeout=timeout)
    except Exception as exc:
        logger.warning("prober: ipv6_leak active probe failed %s: %s", ip, exc)
        return

    if evidence is None:
        return

    _write_event(
        log_path, json_path,
        "ipv6_link_local_leak",
        target_ip=ip,
        ipv6_addr=evidence.get("addr", ""),
        iid_kind=evidence.get("iid_kind", ""),
        mac_oui=evidence.get("mac_oui", ""),
        on_iface=evidence.get("on_iface", ""),
        vector=evidence.get("vector", ""),
        msg=f"IPv6 leak {ip} → {evidence.get('addr', '')} ({evidence.get('iid_kind', '')})",
    )
    logger.info(
        "prober: ipv6_leak %s → %s kind=%s oui=%s",
        ip, evidence.get("addr"), evidence.get("iid_kind"), evidence.get("mac_oui"),
    )
    if publish_fn is not None:
        publish_fn("ipv6_leak", {
            "attacker_ip": ip,
            "addr": evidence.get("addr", ""),
            "iid_kind": evidence.get("iid_kind", ""),
            "mac_oui": evidence.get("mac_oui", ""),
            "vector": evidence.get("vector", ""),
            "on_iface": evidence.get("on_iface", ""),
            "observed_at": evidence.get("observed_at", ""),
        })


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

    loop = asyncio.get_running_loop()

    # Connect to the bus for attacker.fingerprinted fan-out.  Failure is
    # non-fatal: probes still run, results still land in the log file,
    # they just don't push notifications to downstream consumers.
    bus: BaseBus | None = None
    try:
        candidate = get_bus(client_name="prober")
        await candidate.connect()
        bus = candidate
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "prober: bus unavailable, running in publish-off mode: %s", exc,
        )

    raw_publish = make_thread_safe_publisher(bus, loop)

    def _publish_attacker(event_type: str, payload: dict[str, Any]) -> None:
        # Every successful probe fans out under the same topic; the probe
        # family (jarm/hassh/tcpfp) goes in event_type so consumers can
        # filter in-memory without needing a dedicated subscription each.
        raw_publish(
            _topics.attacker(_topics.ATTACKER_FINGERPRINTED),
            payload,
            event_type,
        )

    # Substrate-rotation detection (DEBT-032) — open a sync engine for
    # the prober's lifetime; recorder closes a session per call so we
    # never hold a connection across phase boundaries.  Failure to
    # connect is non-fatal: probes continue, rotation detection is
    # silently disabled.
    rotation_engine: Engine | None = None
    record_rotation: RotationRecorderFn | None = None
    try:
        rotation_engine = _build_sync_engine()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "prober: rotation-detection DB unavailable, "
            "running with rotation detection disabled: %s", exc,
        )

    if rotation_engine is not None:
        def _publish_rotation(event_type: str, payload: dict[str, Any]) -> None:
            raw_publish(
                _topics.attacker(_topics.ATTACKER_FINGERPRINT_ROTATED),
                payload,
                event_type,
            )

        def _syslog_rotation(event_type: str, payload: dict[str, Any]) -> None:
            _write_event(
                log_path, json_path,
                "fingerprint_rotated",
                target_ip=payload["attacker_ip"],
                target_port=str(payload["port"]),
                probe_type=payload["probe_type"],
                old_hash=payload.get("old_hash") or "",
                new_hash=payload["new_hash"],
                rotation_count=str(payload["rotation_count"]),
                msg=(
                    f"FP rotation {payload['attacker_ip']}:{payload['port']} "
                    f"{payload['probe_type']} {payload.get('old_hash')} → "
                    f"{payload['new_hash']}"
                ),
            )

        def record_rotation(
            ip: str, port: int, probe_type: ProbeType, new_hash: str,
        ) -> None:
            with Session(rotation_engine) as session:
                record_fingerprint(
                    session,
                    attacker_ip=ip,
                    port=port,
                    probe_type=probe_type,
                    new_hash=new_hash,
                    ts=datetime.now(timezone.utc),
                    publish_fn=_publish_rotation,
                    syslog_fn=_syslog_rotation,
                )

    shutdown = asyncio.Event()
    heartbeat_task = asyncio.create_task(run_health_heartbeat(bus, "prober"))
    control_task = asyncio.create_task(
        run_control_listener(bus, "prober", shutdown),
    )
    try:
        while not shutdown.is_set():
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
                    _publish_attacker,
                    record_rotation,
                )

            try:
                await asyncio.wait_for(shutdown.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
    finally:
        for t in (heartbeat_task, control_task):
            t.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await t
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()
        if rotation_engine is not None:
            with contextlib.suppress(Exception):
                rotation_engine.dispose()
