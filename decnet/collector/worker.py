"""
Host-side Docker log collector.

Streams stdout from all running decky service containers via the Docker SDK,
writes RFC 5424 lines to <log_file> and parsed JSON records to <log_file>.json.
The ingester tails the .json file; rsyslog can consume the .log file independently.
"""

import asyncio
import contextlib
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from decnet.bus import topics as _topics
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    make_thread_safe_publisher,
    run_control_listener_signal,
    run_health_heartbeat,
)
from decnet.logging import get_logger
from decnet.telemetry import traced as _traced, get_tracer as _get_tracer, inject_context as _inject_ctx

# Collector publish signature: ``publish_fn(parsed_event_dict)``.  Callable
# from the container-stream threads; the worker wraps it around a thread-safe
# bus publisher that marshals onto the asyncio loop.
CollectorPublishFn = Callable[[dict[str, Any]], None]

logger = get_logger("collector")

# ─── Ingestion rate limiter ───────────────────────────────────────────────────
#
# Rationale: connection-lifecycle events (connect/disconnect/accept/close) are
# emitted once per TCP connection. During a portscan or credential-stuffing
# run, a single attacker can generate hundreds of these per second from the
# honeypot services themselves — each becoming a tiny WAL-write transaction
# through the ingester, starving reads until the queue drains.
#
# The collector still writes every line to the raw .log file (forensic record
# for rsyslog/SIEM). Only the .json path — which feeds SQLite — is deduped.
#
# Dedup key: (attacker_ip, decky, service, event_type)
# Window:    DECNET_COLLECTOR_RL_WINDOW_SEC seconds (default 1.0)
# Scope:     DECNET_COLLECTOR_RL_EVENT_TYPES comma list
#            (default: connect,disconnect,connection,accept,close)
# Events outside that set bypass the limiter untouched.

def _parse_float_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError:
        logger.warning("collector: invalid %s=%r, using default %s", name, raw, default)
        return default
    return max(0.0, value)


_RL_WINDOW_SEC: float = _parse_float_env("DECNET_COLLECTOR_RL_WINDOW_SEC", 1.0)
_RL_EVENT_TYPES: frozenset[str] = frozenset(
    t.strip()
    for t in os.environ.get(
        "DECNET_COLLECTOR_RL_EVENT_TYPES",
        "connect,disconnect,connection,accept,close",
    ).split(",")
    if t.strip()
)
_RL_MAX_ENTRIES: int = 10_000

_rl_lock: threading.Lock = threading.Lock()
_rl_last: dict[tuple[str, str, str, str], float] = {}


def _should_ingest(parsed: dict[str, Any]) -> bool:
    """
    Return True if this parsed event should be written to the JSON ingestion
    stream. Rate-limited connection-lifecycle events return False when another
    event with the same (attacker_ip, decky, service, event_type) was emitted
    inside the dedup window.
    """
    event_type = parsed.get("event_type", "")
    if _RL_WINDOW_SEC <= 0.0 or event_type not in _RL_EVENT_TYPES:
        return True
    key = (
        parsed.get("attacker_ip", "Unknown"),
        parsed.get("decky", ""),
        parsed.get("service", ""),
        event_type,
    )
    now = time.monotonic()
    with _rl_lock:
        last = _rl_last.get(key, 0.0)
        if now - last < _RL_WINDOW_SEC:
            return False
        _rl_last[key] = now
        # Opportunistic GC: when the map grows past the cap, drop entries older
        # than 60 windows (well outside any realistic in-flight dedup range).
        if len(_rl_last) > _RL_MAX_ENTRIES:
            cutoff = now - (_RL_WINDOW_SEC * 60.0)
            stale = [k for k, t in _rl_last.items() if t < cutoff]
            for k in stale:
                del _rl_last[k]
    return True


def _reset_rate_limiter() -> None:
    """Test-only helper — clear dedup state between test cases."""
    with _rl_lock:
        _rl_last.clear()

# ─── RFC 5424 parser ──────────────────────────────────────────────────────────

_RFC5424_RE = re.compile(
    r"^<\d+>1 "
    r"(\S+) "       # 1: TIMESTAMP
    r"(\S+) "       # 2: HOSTNAME (decky name)
    r"(\S+) "       # 3: APP-NAME (service)
    r"\S+ "         # PROCID — NILVALUE ("-") for syslog_bridge emitters,
                    # real PID for native syslog callers like sshd/sudo
                    # routed through rsyslog. Accept both; we don't consume it.
    r"(\S+) "       # 4: MSGID (event_type)
    r"(.+)$",       # 5: SD element + optional MSG
)
_SD_BLOCK_RE = re.compile(r'\[relay@55555\s+(.*?)\]', re.DOTALL)
_PARAM_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
_IP_FIELDS = ("src_ip", "src", "client_ip", "remote_ip", "remote_addr", "target_ip", "ip")

# Free-form `key=value` pairs in the MSG body. Used for lines that bypass the
# syslog_bridge SD format — e.g. the SSH container's PROMPT_COMMAND which
# calls `logger -t bash "CMD uid=0 user=root src=1.2.3.4 pwd=/root cmd=…"`.
# Values run until the next whitespace, so `cmd=…` at end-of-line is preserved
# as one unit; we only care about IP-shaped fields here anyway.
_MSG_KV_RE = re.compile(r'(\w+)=(\S+)')


def parse_rfc5424(line: str) -> Optional[dict[str, Any]]:
    """
    Parse an RFC 5424 DECNET log line into a structured dict.
    Returns None if the line does not match the expected format.
    """
    m = _RFC5424_RE.match(line)
    if not m:
        return None
    ts_raw, decky, service, event_type, sd_rest = m.groups()

    fields: dict[str, str] = {}
    msg: str = ""

    if sd_rest.startswith("-"):
        msg = sd_rest[1:].lstrip()
    elif sd_rest.startswith("["):
        block = _SD_BLOCK_RE.search(sd_rest)
        if block:
            for k, v in _PARAM_RE.findall(block.group(1)):
                fields[k] = v.replace('\\"', '"').replace("\\\\", "\\").replace("\\]", "]")
            msg_match = re.search(r'\]\s+(.+)$', sd_rest)
            if msg_match:
                msg = msg_match.group(1).strip()
    else:
        msg = sd_rest

    attacker_ip = "Unknown"
    for fname in _IP_FIELDS:
        if fname in fields:
            attacker_ip = fields[fname]
            break

    # Fallback for plain `logger` callers that don't use SD params (notably
    # the SSH container's bash PROMPT_COMMAND: `logger -t bash "CMD … src=IP …"`).
    # Scan the MSG body for IP-shaped `key=value` tokens ONLY — don't fold
    # them into `fields`, because the frontend's parseEventBody already
    # renders kv pairs from the msg and doubling them up produces noisy
    # duplicate pills. This keeps attacker attribution working without
    # changing the shape of `fields` for non-SD lines.
    if attacker_ip == "Unknown" and msg:
        for k, v in _MSG_KV_RE.findall(msg):
            if k in _IP_FIELDS:
                attacker_ip = v
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


# ─── Container helpers ────────────────────────────────────────────────────────

def _load_service_container_names() -> set[str]:
    """
    Return the exact set of service container names from decnet-state.json.
    Format: {decky_name}-{service_name}, e.g. 'omega-decky-smtp'.
    Returns an empty set if no state file exists.
    """
    from decnet.config import load_state
    state = load_state()
    if state is None:
        return set()
    config, _ = state
    names: set[str] = set()
    for decky in config.deckies:
        for svc in decky.services:
            names.add(f"{decky.name}-{svc.replace('_', '-')}")
    return names


_TOPOLOGY_SERVICE_LABEL = "decnet.topology.service"
_FLEET_SERVICE_LABEL = "decnet.fleet.service"


def _has_decnet_service_label(labels: Optional[dict]) -> bool:
    """Recognize both fleet (``decnet.fleet.service``, set by
    ``decnet/composer.py``) and MazeNET topology (``decnet.topology.service``,
    set by ``decnet/topology/compose.py``) containers.

    Label-based detection is the canonical path: it's stateless and avoids
    the race between ``docker compose up`` and the ``decnet-state.json``
    write that previously caused freshly-deployed fleet containers to be
    silently dropped by the docker-events watcher.
    """
    if not labels:
        return False
    return (
        labels.get(_TOPOLOGY_SERVICE_LABEL) == "true"
        or labels.get(_FLEET_SERVICE_LABEL) == "true"
    )


def is_service_container(container) -> bool:
    """Return True if this Docker container is a known DECNET service container.

    Label-based detection is preferred (works for both fleet and MazeNET
    topology containers without touching decnet-state.json). The
    state-file name match remains as a fallback so containers built from
    older composes — which predate the ``decnet.fleet.service`` label —
    are still picked up.
    """
    if isinstance(container, str):
        return container.lstrip("/") in _load_service_container_names()
    labels: Optional[dict] = None
    attrs = getattr(container, "attrs", None)
    if isinstance(attrs, dict):
        labels = (attrs.get("Config") or {}).get("Labels")
    if labels is None:
        labels = getattr(container, "labels", None)
    if _has_decnet_service_label(labels):
        return True
    # Fallback: legacy containers without labels still match by name.
    name = container.name.lstrip("/")
    return name in _load_service_container_names()


def is_service_event(attrs: dict) -> bool:
    """Return True if a Docker start event is for a known DECNET service container.

    Docker start-event attrs flatten every container label alongside the
    ``name``/``image`` keys — no separate ``labels`` sub-dict — so label
    detection happens directly on ``attrs``.

    Prefer the label path because it's race-free with respect to the
    ``decnet-state.json`` write that ``decnet deploy`` performs around
    ``docker compose up``: a freshly-started container's start event can
    arrive before the state file has been updated, and the legacy
    name-based fallback would then drop the event.
    """
    if _has_decnet_service_label(attrs):
        return True
    name = attrs.get("name", "").lstrip("/")
    return name in _load_service_container_names()


# ─── Blocking stream worker (runs in a thread) ────────────────────────────────

def _reopen_if_needed(path: Path, fh: Optional[Any]) -> Any:
    """Return fh if it still points to the same inode as path; otherwise close
    fh and open a fresh handle.  Handles the file being deleted (manual rm) or
    rotated (logrotate rename + create)."""
    try:
        if fh is not None and os.fstat(fh.fileno()).st_ino == os.stat(path).st_ino:
            return fh
    except OSError:
        pass
    # File gone or inode changed — close stale handle and open a new one.
    if fh is not None:
        try:
            fh.close()
        except Exception:  # nosec B110 — best-effort file handle cleanup
            pass
    path.parent.mkdir(parents=True, exist_ok=True)
    return open(path, "a", encoding="utf-8")


@_traced("collector.stream_container")
def _stream_container(
    container_id: str,
    log_path: Path,
    json_path: Path,
    publish_fn: CollectorPublishFn | None = None,
) -> None:
    """Stream logs from one container and append to the host log files."""
    import docker  # type: ignore[import]

    lf: Optional[Any] = None
    jf: Optional[Any] = None
    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        log_stream = container.logs(stream=True, follow=True, stdout=True, stderr=False)
        buf = ""
        for chunk in log_stream:
            buf += chunk.decode("utf-8", errors="replace")
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.rstrip()
                if not line:
                    continue
                lf = _reopen_if_needed(log_path, lf)
                lf.write(line + "\n")
                lf.flush()
                parsed = parse_rfc5424(line)
                if parsed:
                    if _should_ingest(parsed):
                        _tracer = _get_tracer("collector")
                        with _tracer.start_as_current_span("collector.event") as _span:
                            _span.set_attribute("decky", parsed.get("decky", ""))
                            _span.set_attribute("service", parsed.get("service", ""))
                            _span.set_attribute("event_type", parsed.get("event_type", ""))
                            _span.set_attribute("attacker_ip", parsed.get("attacker_ip", ""))
                            _inject_ctx(parsed)
                            logger.debug("collector: event written decky=%s type=%s", parsed.get("decky"), parsed.get("event_type"))
                            jf = _reopen_if_needed(json_path, jf)
                            jf.write(json.dumps(parsed) + "\n")
                            jf.flush()
                            if publish_fn is not None:
                                try:
                                    publish_fn(parsed)
                                except Exception as exc:
                                    logger.debug(
                                        "collector: bus publish failed: %s", exc,
                                    )
                    else:
                        logger.debug(
                            "collector: rate-limited decky=%s service=%s type=%s attacker=%s",
                            parsed.get("decky"), parsed.get("service"),
                            parsed.get("event_type"), parsed.get("attacker_ip"),
                        )
                else:
                    logger.debug("collector: malformed RFC5424 line snippet=%r", line[:80])
    except Exception as exc:
        logger.debug("collector: log stream ended container_id=%s reason=%s", container_id, exc)
    finally:
        for fh in (lf, jf):
            if fh is not None:
                try:
                    fh.close()
                except Exception:  # nosec B110 — best-effort file handle cleanup
                    pass


# ─── Bus plumbing ─────────────────────────────────────────────────────────────

def _make_system_log_publisher(
    bus: Any, loop: asyncio.AbstractEventLoop,
) -> CollectorPublishFn:
    """Factory: returns a ``publish_fn(parsed)`` for use by stream threads.

    When *bus* is ``None`` the returned callable is a no-op, so the stream
    thread can call it unconditionally.  Otherwise each call is marshalled
    onto *loop* (the asyncio event loop that owns the bus socket) via
    ``make_thread_safe_publisher``.
    """
    raw_publish = make_thread_safe_publisher(bus, loop) if bus is not None else None
    if raw_publish is None:
        return lambda _parsed: None

    topic = _topics.system(_topics.SYSTEM_LOG)

    def _publish(parsed: dict[str, Any]) -> None:
        event_type = parsed.get("event_type", "")
        raw_publish(
            topic,
            {
                "decky": parsed.get("decky", ""),
                "service": parsed.get("service", ""),
                "event_type": event_type,
                "attacker_ip": parsed.get("attacker_ip", "Unknown"),
                "timestamp": parsed.get("timestamp", ""),
            },
            event_type,
        )

    return _publish


# ─── Async collector ──────────────────────────────────────────────────────────

async def log_collector_worker(log_file: str) -> None:
    """
    Background task: streams Docker logs from all running decky service
    containers, writing RFC 5424 lines to log_file and parsed JSON records
    to log_file.json for the ingester to consume.

    Watches Docker events to pick up containers started after initial scan.
    """
    import docker  # type: ignore[import]

    log_path = Path(log_file)
    json_path = log_path.with_suffix(".json")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    active: dict[str, asyncio.Task[None]] = {}
    loop = asyncio.get_running_loop()

    # Optional bus wiring — per-line system.log publish.  Fan-in from many
    # container-stream threads is handled by make_thread_safe_publisher,
    # which marshals each publish onto this loop.
    bus = None
    try:
        bus = get_bus(client_name="collector")
        await bus.connect()
    except Exception as exc:
        logger.warning("collector: bus unavailable, continuing without publish: %s", exc)
        bus = None

    _publish_log = _make_system_log_publisher(bus, loop)

    # Workers panel health heartbeat + bus-driven stop control.  The
    # heartbeat beacons on system.collector.health every 30s; the
    # control listener translates a bus stop intent into a SIGTERM to
    # this process (collector's main loop is a blocking thread pool, so
    # self-signalling is cleaner than threading a shutdown event).
    heartbeat_task = asyncio.create_task(run_health_heartbeat(bus, "collector"))
    control_task = asyncio.create_task(run_control_listener_signal(bus, "collector"))

    # Dedicated thread pool so long-running container log streams don't
    # saturate the default asyncio executor and starve short-lived
    # to_thread() calls elsewhere (e.g. load_state in the web API).
    collector_pool = ThreadPoolExecutor(
        max_workers=64, thread_name_prefix="decnet-collector",
    )

    def _spawn(container_id: str, container_name: str) -> None:
        if container_id not in active or active[container_id].done():
            active[container_id] = asyncio.ensure_future(
                loop.run_in_executor(
                    collector_pool, _stream_container,
                    container_id, log_path, json_path, _publish_log,
                ),
                loop=loop,
            )
            logger.info("collector: streaming container=%s", container_name)

    try:
        logger.info("collector started log_path=%s", log_path)
        client = docker.from_env()

        for container in client.containers.list():
            if is_service_container(container):
                _spawn(container.id, container.name.lstrip("/"))

        def _watch_events() -> None:
            for event in client.events(
                decode=True,
                filters={"type": "container", "event": "start"},
            ):
                attrs = event.get("Actor", {}).get("Attributes", {})
                cid  = event.get("id", "")
                name = attrs.get("name", "")
                if cid and is_service_event(attrs):
                    loop.call_soon_threadsafe(_spawn, cid, name)

        await loop.run_in_executor(collector_pool, _watch_events)

    except asyncio.CancelledError:
        logger.info("collector shutdown requested cancelling %d tasks", len(active))
        for task in active.values():
            task.cancel()
        collector_pool.shutdown(wait=False)
        raise
    except Exception as exc:
        logger.error("collector error: %s", exc)
    finally:
        collector_pool.shutdown(wait=False)
        for t in (heartbeat_task, control_task):
            t.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await t
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()
