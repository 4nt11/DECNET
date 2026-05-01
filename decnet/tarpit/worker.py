"""Tarpit connection watcher — edge-triggered enter/exit log events.

Polls active tarpit rules every ``DECNET_TARPIT_POLL_INTERVAL`` seconds
(default 15).  For each rule, reads ``/proc/{pid}/net/tcp`` on the host
(no docker exec, no ss needed inside the container) to find ESTABLISHED
connections on the tarpitted ports.  Emits structured log events:

* ``tarpit_enter`` — new connection seen on a tarpitted port
* ``tarpit_exit``  — connection gone; includes elapsed time in seconds

Runs embedded in the API process (always-on, near-zero cost when no
rules exist).
"""
from __future__ import annotations

import asyncio
import json
import socket
from datetime import datetime, timezone
from typing import Any, Optional

from decnet.decky_io.resolve import resolve_decky_container
from decnet.logging import get_logger
from decnet.network import get_container_pid
from decnet.web.db.repository import BaseRepository

log = get_logger("tarpit.watcher")

_POLL_INTERVAL_ENV = "DECNET_TARPIT_POLL_INTERVAL"
_DEFAULT_POLL_S = 15

_TCP_ESTABLISHED = "01"


def _read_proc_net_tcp(pid: int) -> str:
    """Read /proc/{pid}/net/tcp from the host (namespace-aware symlink)."""
    path = f"/proc/{pid}/net/tcp"
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _parse_connections(content: str, target_port: int) -> list[str]:
    """Return list of remote IPs in ESTABLISHED state on target_port."""
    ips: list[str] = []
    for line in content.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        local_hex, rem_hex, state = parts[1], parts[2], parts[3]
        if state != _TCP_ESTABLISHED:
            continue
        local_port = int(local_hex.split(":")[1], 16)
        if local_port != target_port:
            continue
        rem_ip_hex = rem_hex.split(":")[0]
        try:
            ip_bytes = bytes.fromhex(rem_ip_hex)[::-1]
            ip = socket.inet_ntoa(ip_bytes)
        except (ValueError, OSError):
            continue
        if ip != "0.0.0.0":  # nosec B104
            ips.append(ip)
    return ips


def _get_poll_interval() -> int:
    import os
    try:
        return int(os.environ.get(_POLL_INTERVAL_ENV, _DEFAULT_POLL_S))
    except (TypeError, ValueError):
        return _DEFAULT_POLL_S


async def _get_attacker_uuid(repo: BaseRepository, ip: str) -> Optional[str]:
    try:
        from decnet.web.db.models import Attacker
        from sqlalchemy import select
        async with repo._session() as session:  # type: ignore[attr-defined]
            result = await session.execute(
                select(Attacker).where(Attacker.ip == ip)  # type: ignore[arg-type]
            )
            row = result.scalar_one_or_none()
            return row.uuid if row else None
    except Exception:
        return None


async def _emit_log(
    repo: BaseRepository,
    *,
    event_type: str,
    decky_name: str,
    src_ip: str,
    port: int,
    extra: dict[str, Any] | None = None,
) -> None:
    attacker_uuid = await _get_attacker_uuid(repo, src_ip)
    fields: dict[str, Any] = {"port": port, "attacker_uuid": attacker_uuid}
    if extra:
        fields.update(extra)
    try:
        await repo.add_log({
            "decky": decky_name,
            "service": "tarpit",
            "event_type": event_type,
            "attacker_ip": src_ip,
            "raw_line": f"tarpit {event_type} src={src_ip} decky={decky_name} port={port}",
            "fields": json.dumps(fields),
        })
    except Exception as exc:
        log.warning("tarpit log emit failed: %s", exc)


async def tarpit_watcher_worker(repo: BaseRepository) -> None:
    """Main loop — runs forever, wakes every DECNET_TARPIT_POLL_INTERVAL seconds."""
    poll_interval = _get_poll_interval()
    log.info("tarpit watcher started poll_interval=%ds", poll_interval)

    # (decky_name, src_ip, port) → first_seen timestamp
    seen: dict[tuple[str, str, int], datetime] = {}

    while True:
        try:
            await _tick(repo, seen)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("tarpit watcher tick error: %s", exc)
        await asyncio.sleep(poll_interval)


async def _tick(
    repo: BaseRepository,
    seen: dict[tuple[str, str, int], datetime],
) -> None:
    rules = await repo.list_tarpit_rules()
    if not rules:
        # No active tarpit rules — clear stale seen state and bail early.
        seen.clear()
        return

    current: set[tuple[str, str, int]] = set()

    for rule in rules:
        db_key: str = rule["decky_name"]
        ports: list[int] = rule["ports"]

        # Topology deckies are stored as "t:{topology_id}:{decky_name}".
        # Resolve the real container name before asking Docker for its PID.
        if db_key.startswith("t:"):
            _, topology_id, decky_name = db_key.split(":", 2)
            try:
                container = await resolve_decky_container(
                    repo, decky_name, topology_id=topology_id,
                )
            except LookupError as exc:
                log.debug("tarpit watcher: %s", exc)
                continue
        else:
            decky_name = db_key
            container = db_key

        try:
            pid = await asyncio.to_thread(get_container_pid, container)
        except LookupError as exc:
            log.debug("tarpit watcher: %s", exc)
            continue

        tcp_content = await asyncio.to_thread(_read_proc_net_tcp, pid)

        for port in ports:
            for src_ip in _parse_connections(tcp_content, port):
                key = (decky_name, src_ip, port)
                current.add(key)
                if key not in seen:
                    seen[key] = datetime.now(timezone.utc)
                    log.info(
                        "tarpit enter decky=%s src=%s port=%d",
                        decky_name, src_ip, port,
                    )
                    await _emit_log(
                        repo,
                        event_type="tarpit_enter",
                        decky_name=decky_name,
                        src_ip=src_ip,
                        port=port,
                    )

    for key in list(seen):
        if key not in current:
            first_seen = seen.pop(key)
            elapsed = int((datetime.now(timezone.utc) - first_seen).total_seconds())
            decky_name, src_ip, port = key
            log.info(
                "tarpit exit decky=%s src=%s port=%d elapsed=%ds",
                decky_name, src_ip, port, elapsed,
            )
            await _emit_log(
                repo,
                event_type="tarpit_exit",
                decky_name=decky_name,
                src_ip=src_ip,
                port=port,
                extra={"duration_s": elapsed},
            )
