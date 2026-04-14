"""
Attacker profile builder — background worker.

Periodically rebuilds the `attackers` table by:
  1. Feeding all stored Log.raw_line values through the CorrelationEngine
     (which parses RFC 5424 and tracks per-IP event histories + traversals).
  2. Merging with the Bounty table (fingerprints, credentials).
  3. Extracting commands executed per IP from the structured log fields.
  4. Upserting one Attacker record per observed IP.

Runs every _REBUILD_INTERVAL seconds. Full rebuild each cycle — simple and
correct at honeypot log volumes.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

from decnet.correlation.engine import CorrelationEngine
from decnet.correlation.parser import LogEvent
from decnet.logging import get_logger
from decnet.web.db.repository import BaseRepository

logger = get_logger("attacker_worker")

_REBUILD_INTERVAL = 30  # seconds

# Event types that indicate active command/query execution (not just connection/scan)
_COMMAND_EVENT_TYPES = frozenset({
    "command", "exec", "query", "input", "shell_input",
    "execute", "run", "sql_query", "redis_command",
})

# Fields that carry the executed command/query text
_COMMAND_FIELDS = ("command", "query", "input", "line", "sql", "cmd")


async def attacker_profile_worker(repo: BaseRepository) -> None:
    """Periodically rebuilds the Attacker table. Designed to run as an asyncio Task."""
    logger.info("attacker profile worker started interval=%ds", _REBUILD_INTERVAL)
    while True:
        await asyncio.sleep(_REBUILD_INTERVAL)
        try:
            await _rebuild(repo)
        except Exception as exc:
            logger.error("attacker worker: rebuild failed: %s", exc)


async def _rebuild(repo: BaseRepository) -> None:
    all_logs = await repo.get_all_logs_raw()
    if not all_logs:
        return

    # Feed raw RFC 5424 lines into the CorrelationEngine
    engine = CorrelationEngine()
    for row in all_logs:
        engine.ingest(row["raw_line"])

    if not engine._events:
        return

    traversal_map = {t.attacker_ip: t for t in engine.traversals(min_deckies=2)}
    all_bounties = await repo.get_all_bounties_by_ip()

    count = 0
    for ip, events in engine._events.items():
        traversal = traversal_map.get(ip)
        bounties = all_bounties.get(ip, [])
        commands = _extract_commands(all_logs, ip)

        record = _build_record(ip, events, traversal, bounties, commands)
        await repo.upsert_attacker(record)
        count += 1

    logger.debug("attacker worker: rebuilt %d profiles", count)


def _build_record(
    ip: str,
    events: list[LogEvent],
    traversal: Any,
    bounties: list[dict[str, Any]],
    commands: list[dict[str, Any]],
) -> dict[str, Any]:
    services = sorted({e.service for e in events})
    deckies = (
        traversal.deckies
        if traversal
        else _first_contact_deckies(events)
    )
    fingerprints = [b for b in bounties if b.get("bounty_type") == "fingerprint"]
    credential_count = sum(1 for b in bounties if b.get("bounty_type") == "credential")

    return {
        "ip": ip,
        "first_seen": min(e.timestamp for e in events),
        "last_seen": max(e.timestamp for e in events),
        "event_count": len(events),
        "service_count": len(services),
        "decky_count": len({e.decky for e in events}),
        "services": json.dumps(services),
        "deckies": json.dumps(deckies),
        "traversal_path": traversal.path if traversal else None,
        "is_traversal": traversal is not None,
        "bounty_count": len(bounties),
        "credential_count": credential_count,
        "fingerprints": json.dumps(fingerprints),
        "commands": json.dumps(commands),
        "updated_at": datetime.now(timezone.utc),
    }


def _first_contact_deckies(events: list[LogEvent]) -> list[str]:
    """Return unique deckies in first-contact order (for non-traversal attackers)."""
    seen: list[str] = []
    for e in sorted(events, key=lambda x: x.timestamp):
        if e.decky not in seen:
            seen.append(e.decky)
    return seen


def _extract_commands(
    all_logs: list[dict[str, Any]], ip: str
) -> list[dict[str, Any]]:
    """
    Extract executed commands for a given attacker IP from raw log rows.

    Looks for rows where:
    - attacker_ip matches
    - event_type is a known command-execution type
    - fields JSON contains a command-like key

    Returns a list of {service, decky, command, timestamp} dicts.
    """
    commands: list[dict[str, Any]] = []
    for row in all_logs:
        if row.get("attacker_ip") != ip:
            continue
        if row.get("event_type") not in _COMMAND_EVENT_TYPES:
            continue

        raw_fields = row.get("fields")
        if not raw_fields:
            continue

        # fields is stored as a JSON string in the DB row
        if isinstance(raw_fields, str):
            try:
                fields = json.loads(raw_fields)
            except (json.JSONDecodeError, ValueError):
                continue
        else:
            fields = raw_fields

        cmd_text: str | None = None
        for key in _COMMAND_FIELDS:
            val = fields.get(key)
            if val:
                cmd_text = str(val)
                break

        if not cmd_text:
            continue

        ts = row.get("timestamp")
        commands.append({
            "service": row.get("service", ""),
            "decky": row.get("decky", ""),
            "command": cmd_text,
            "timestamp": ts.isoformat() if isinstance(ts, datetime) else str(ts),
        })

    return commands
