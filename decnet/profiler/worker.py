"""
Attacker profile builder — incremental background worker.

Maintains a persistent CorrelationEngine and a log-ID cursor across cycles.
On cold start (first cycle or process restart), performs one full build from
all stored logs.  Subsequent cycles fetch only new logs via the cursor,
ingest them into the existing engine, and rebuild profiles for affected IPs
only.

Complexity per cycle: O(new_logs + affected_ips) instead of O(total_logs²).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from decnet.correlation.engine import CorrelationEngine
from decnet.correlation.parser import LogEvent
from decnet.logging import get_logger
from decnet.profiler.behavioral import build_behavior_record
from decnet.web.db.repository import BaseRepository

logger = get_logger("attacker_worker")

_BATCH_SIZE = 500
_STATE_KEY = "attacker_worker_cursor"

# Event types that indicate active command/query execution (not just connection/scan)
_COMMAND_EVENT_TYPES = frozenset({
    "command", "exec", "query", "input", "shell_input",
    "execute", "run", "sql_query", "redis_command",
})

# Fields that carry the executed command/query text
_COMMAND_FIELDS = ("command", "query", "input", "line", "sql", "cmd")


@dataclass
class _WorkerState:
    engine: CorrelationEngine = field(default_factory=CorrelationEngine)
    last_log_id: int = 0
    initialized: bool = False


async def attacker_profile_worker(repo: BaseRepository, *, interval: int = 30) -> None:
    """Periodically updates the Attacker table incrementally. Designed to run as an asyncio Task."""
    logger.info("attacker profile worker started interval=%ds", interval)
    state = _WorkerState()
    while True:
        await asyncio.sleep(interval)
        try:
            await _incremental_update(repo, state)
        except Exception as exc:
            logger.error("attacker worker: update failed: %s", exc)


async def _incremental_update(repo: BaseRepository, state: _WorkerState) -> None:
    was_cold = not state.initialized
    affected_ips: set[str] = set()

    while True:
        batch = await repo.get_logs_after_id(state.last_log_id, limit=_BATCH_SIZE)
        if not batch:
            break

        for row in batch:
            event = state.engine.ingest(row["raw_line"])
            if event and event.attacker_ip:
                affected_ips.add(event.attacker_ip)
            state.last_log_id = row["id"]

        await asyncio.sleep(0)  # yield to event loop after each batch

        if len(batch) < _BATCH_SIZE:
            break

    state.initialized = True

    if not affected_ips:
        await repo.set_state(_STATE_KEY, {"last_log_id": state.last_log_id})
        return

    await _update_profiles(repo, state, affected_ips)
    await repo.set_state(_STATE_KEY, {"last_log_id": state.last_log_id})

    if was_cold:
        logger.info("attacker worker: cold start rebuilt %d profiles", len(affected_ips))
    else:
        logger.info("attacker worker: updated %d profiles (incremental)", len(affected_ips))


async def _update_profiles(
    repo: BaseRepository,
    state: _WorkerState,
    ips: set[str],
) -> None:
    traversal_map = {t.attacker_ip: t for t in state.engine.traversals(min_deckies=2)}
    bounties_map = await repo.get_bounties_for_ips(ips)

    for ip in ips:
        events = state.engine._events.get(ip, [])
        if not events:
            continue

        traversal = traversal_map.get(ip)
        bounties = bounties_map.get(ip, [])
        commands = _extract_commands_from_events(events)

        record = _build_record(ip, events, traversal, bounties, commands)
        attacker_uuid = await repo.upsert_attacker(record)

        # Behavioral / fingerprint rollup lives in a sibling table so failures
        # here never block the core attacker profile upsert.
        try:
            behavior = build_behavior_record(events)
            await repo.upsert_attacker_behavior(attacker_uuid, behavior)
        except Exception as exc:
            logger.error("attacker worker: behavior upsert failed for %s: %s", ip, exc)


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


def _extract_commands_from_events(events: list[LogEvent]) -> list[dict[str, Any]]:
    """
    Extract executed commands from LogEvent objects.

    Works directly on LogEvent.fields (already a dict), so no JSON parsing needed.
    """
    commands: list[dict[str, Any]] = []
    for event in events:
        if event.event_type not in _COMMAND_EVENT_TYPES:
            continue

        cmd_text: str | None = None
        for key in _COMMAND_FIELDS:
            val = event.fields.get(key)
            if val:
                cmd_text = str(val)
                break

        if not cmd_text:
            continue

        commands.append({
            "service": event.service,
            "decky": event.decky,
            "command": cmd_text,
            "timestamp": event.timestamp.isoformat(),
        })

    return commands
