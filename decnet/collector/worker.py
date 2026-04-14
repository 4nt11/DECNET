"""
Host-side Docker log collector.

Streams stdout from all running decky service containers via the Docker SDK,
writes RFC 5424 lines to <log_file> and parsed JSON records to <log_file>.json.
The ingester tails the .json file; rsyslog can consume the .log file independently.
"""

import asyncio
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from decnet.logging import get_logger

logger = get_logger("collector")

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

# bash PROMPT_COMMAND logger output: "CMD uid=0 pwd=/root cmd=ls -lah"
_BASH_CMD_RE = re.compile(r"CMD\s+uid=(\S+)\s+pwd=(\S+)\s+cmd=(.*)")



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

    # Normalize bash CMD lines from SSH honeypot PROMPT_COMMAND logger
    if service == "bash" and msg:
        cmd_match = _BASH_CMD_RE.match(msg)
        if cmd_match:
            service = "ssh"
            event_type = "command"
            fields["uid"] = cmd_match.group(1)
            fields["pwd"] = cmd_match.group(2)
            fields["command"] = cmd_match.group(3)

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


def is_service_container(container) -> bool:
    """Return True if this Docker container is a known DECNET service container."""
    name = (container if isinstance(container, str) else container.name).lstrip("/")
    return name in _load_service_container_names()


def is_service_event(attrs: dict) -> bool:
    """Return True if a Docker start event is for a known DECNET service container."""
    name = attrs.get("name", "").lstrip("/")
    return name in _load_service_container_names()


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
                        logger.debug("collector: event written decky=%s type=%s", parsed.get("decky"), parsed.get("event_type"))
                        jf.write(json.dumps(parsed) + "\n")
                        jf.flush()
                    else:
                        logger.debug("collector: malformed RFC5424 line snippet=%r", line[:80])
    except Exception as exc:
        logger.debug("collector: log stream ended container_id=%s reason=%s", container_id, exc)


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

        await asyncio.to_thread(_watch_events)

    except asyncio.CancelledError:
        logger.info("collector shutdown requested cancelling %d tasks", len(active))
        for task in active.values():
            task.cancel()
        raise
    except Exception as exc:
        logger.error("collector error: %s", exc)
