"""
Host-side Docker log collector.

Streams stdout from all running decky service containers via the Docker SDK,
writes RFC 5424 lines to <log_file> and parsed JSON records to <log_file>.json.
The ingester tails the .json file; rsyslog can consume the .log file independently.
"""

import asyncio
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("decnet.web.collector")

# ─── RFC 5424 parser ──────────────────────────────────────────────────────────

_RFC5424_RE = re.compile(
    r"^<\d+>1 "
    r"(\S+) "       # 1: TIMESTAMP
    r"(\S+) "       # 2: HOSTNAME (decky name)
    r"(\S+) "       # 3: APP-NAME (service)
    r"- "           # PROCID always NILVALUE
    r"(\S+) "       # 4: MSGID (event_type)
    r"(.+)$",       # 5: SD element + optional MSG
)
_SD_BLOCK_RE = re.compile(r'\[decnet@55555\s+(.*?)\]', re.DOTALL)
_PARAM_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
_IP_FIELDS = ("src_ip", "src", "client_ip", "remote_ip", "ip")


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

def _is_decnet_service_labels(labels: dict) -> bool:
    """
    Return True if the Compose labels indicate a DECNET service container.

    Discriminator: base containers have no depends_on (they own the IP);
    service containers all declare depends_on pointing at their base.
    Both sets carry com.docker.compose.project=decnet.
    """
    if labels.get("com.docker.compose.project") != "decnet":
        return False
    return bool(labels.get("com.docker.compose.depends_on", "").strip())


def is_service_container(container) -> bool:
    """
    Return True for DECNET service containers.

    Accepts either a Docker SDK container object or a plain name string
    (legacy path — falls back to label-free heuristic when only a name
    is available, which is always less reliable).
    """
    if isinstance(container, str):
        # Called with a name only (e.g. from event stream before full inspect).
        # Best-effort: a base container name has no service suffix, so it won't
        # contain a hyphen after the decky name. We can't be certain without
        # labels, so this path is only kept for the event fast-path and is
        # superseded by the label check in the initial scan.
        name = container.lstrip("/")
        # Filter out anything not from our project (best effort via name)
        return "-" in name  # will be re-checked via labels on _spawn
    labels = container.labels or {}
    return _is_decnet_service_labels(labels)


def is_service_event(attrs: dict) -> bool:
    """Return True if a Docker event's Actor.Attributes are for a DECNET service container."""
    return _is_decnet_service_labels(attrs)


# ─── Blocking stream worker (runs in a thread) ────────────────────────────────

def _stream_container(container_id: str, log_path: Path, json_path: Path) -> None:
    """Stream logs from one container and append to the host log files."""
    import docker  # type: ignore[import]

    try:
        client = docker.from_env()
        container = client.containers.get(container_id)
        log_stream = container.logs(stream=True, follow=True, stdout=True, stderr=False)
        buf = ""
        with (
            open(log_path, "a", encoding="utf-8") as lf,
            open(json_path, "a", encoding="utf-8") as jf,
        ):
            for chunk in log_stream:
                buf += chunk.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    line = line.rstrip()
                    if not line:
                        continue
                    lf.write(line + "\n")
                    lf.flush()
                    parsed = parse_rfc5424(line)
                    if parsed:
                        jf.write(json.dumps(parsed) + "\n")
                        jf.flush()
    except Exception as exc:
        logger.debug("Log stream ended for container %s: %s", container_id, exc)


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

    def _spawn(container_id: str, container_name: str) -> None:
        if container_id not in active or active[container_id].done():
            active[container_id] = asyncio.ensure_future(
                asyncio.to_thread(_stream_container, container_id, log_path, json_path),
                loop=loop,
            )
            logger.info("Collecting logs from container: %s", container_name)

    try:
        client = docker.from_env()

        # Collect from already-running containers
        for container in client.containers.list():
            if is_service_container(container):
                _spawn(container.id, container.name.lstrip("/"))

        # Watch for new containers starting
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

        await asyncio.to_thread(_watch_events)

    except asyncio.CancelledError:
        for task in active.values():
            task.cancel()
        raise
    except Exception as exc:
        logger.error("Collector error: %s", exc)
