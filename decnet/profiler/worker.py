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
import contextlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from decnet.artifacts.shards import find_shard_with_sid
from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus, Event
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    make_thread_safe_publisher,
    run_control_listener,
    run_health_heartbeat,
)
from decnet.correlation.engine import CorrelationEngine
from decnet.correlation.parser import LogEvent
from decnet.asn import enrich_ip as enrich_ip_asn
from decnet.geoip import enrich_ip
from decnet.geoip.ptr import resolve_ptr_record
from decnet.logging import get_logger
from decnet.profiler.behave_shell._handler import handle_session_ended
from decnet.profiler.behavioral import build_behavior_record
from decnet.telemetry import traced as _traced, get_tracer as _get_tracer
from decnet.web.db.repository import BaseRepository

logger = get_logger("attacker_worker")

_BATCH_SIZE = 500
_STATE_KEY = "attacker_worker_cursor"
# Separate cursor for the BEHAVE-SHELL poll fallback so it doesn't
# conflate with the correlation tick's log-id cursor (memory rule:
# "Poll fallback's Log cursor — use a separate state key").
_BEHAVE_POLL_STATE_KEY = "attacker_worker_session_cursor"
# Pattern the bus subscription matches. Single-topic for BEHAVE-SHELL
# wiring; matches what the collector publishes from
# ``_SessionAggregator._emit_session``.
_BEHAVE_TOPIC = _topics.attacker(_topics.ATTACKER_SESSION_ENDED)

# Event types that indicate active command/query execution — the
# shell-family subset of INTERACTION_EVENT_TYPES in
# decnet/correlation/event_kinds.py. Kept here because this set is a
# stricter filter (commands that carry text to extract, vs. interactions
# like RCPT TO or file upload that don't). A test in
# tests/profiler/ asserts it's a subset of the canonical interaction
# set so they can't drift.
_COMMAND_EVENT_TYPES = frozenset({
    "command", "exec", "query", "input", "shell_input",
    "execute", "run", "sql_query", "redis_command",
})

# Fields that carry the executed command/query text
_COMMAND_FIELDS = ("command", "query", "input", "line", "sql", "cmd")

# SMTP events that carry a recipient email address. `rcpt_to` fires once per
# accepted RCPT (open-relay mode), `rcpt_denied` once per denied RCPT
# (harvester mode). `message_accepted` carries the comma-joined rcpt list
# on the final DATA commit — covered for replay safety, though every
# address it contains already arrived via `rcpt_to` earlier in the session.
_SMTP_RCPT_EVENTS = frozenset({"rcpt_to", "rcpt_denied", "message_accepted"})

# Pseudo-TLDs we never want to report on: the RFC 6761 special-use names
# plus common lab-only values. Matching happens on the *last* label so
# `foo.example.com` is filtered but `example.corp` is not.
_BLOCKED_TLDS = frozenset({"invalid", "test", "localhost", "local", "example"})


@dataclass
class _WorkerState:
    engine: CorrelationEngine = field(default_factory=CorrelationEngine)
    last_log_id: int = 0
    initialized: bool = False
    # Optional bus hook — fires ``("scored", payload)`` per profile upsert.
    # None when the bus is disabled or unreachable.
    publish_attacker: Callable[[str, dict[str, Any]], None] | None = None
    # Set of IPs we've already tried to PTR-resolve in this worker's
    # lifetime. Bounds retry to once per worker boot so a persistently
    # NXDOMAIN-returning IP doesn't burn 2s of tick time on every cycle.
    ptr_attempted: set[str] = field(default_factory=set)


async def attacker_profile_worker(repo: BaseRepository, *, interval: int = 30) -> None:
    """Periodically updates the Attacker table incrementally. Designed to run as an asyncio Task."""
    logger.info("attacker profile worker started interval=%ds", interval)

    # Optional bus wiring — correlator-family publishes ride on the profiler
    # worker because CorrelationEngine lives inside it.  If the bus is off or
    # unreachable the engine runs with publish_fn=None and downstream degrades
    # to DB-only.
    bus = None
    try:
        bus = get_bus(client_name="profiler")
        await bus.connect()
    except Exception as exc:
        logger.warning("profiler: bus unavailable, continuing without publish: %s", exc)
        bus = None

    loop = asyncio.get_running_loop()
    raw_publish = make_thread_safe_publisher(bus, loop) if bus is not None else None

    def _publish_attacker(event_type: str, payload: dict[str, Any]) -> None:
        if raw_publish is None:
            return
        raw_publish(_topics.attacker(event_type), payload, event_type)

    state = _WorkerState(
        engine=CorrelationEngine(publish_fn=_publish_attacker),
        publish_attacker=_publish_attacker,
    )
    _saved_cursor = await repo.get_state(_STATE_KEY)
    if _saved_cursor:
        state.last_log_id = _saved_cursor.get("last_log_id", 0)
        state.initialized = True
        logger.info("attacker worker: resumed from cursor last_log_id=%d", state.last_log_id)

    # Workers panel wiring: heartbeat + bus-driven stop.  Main loop is
    # pure asyncio sleep/await, so an event-based control listener
    # drops in cleanly without a SIGTERM self-signal.
    shutdown = asyncio.Event()
    heartbeat_task = asyncio.create_task(run_health_heartbeat(bus, "profiler"))
    control_task = asyncio.create_task(
        run_control_listener(bus, "profiler", shutdown),
    )

    # BEHAVE-SHELL session-ended handler — bus subscription pump (when
    # bus is available) feeds an asyncio.Queue; the tick body drains
    # the queue per iteration. Same shape as decnet/ttp/worker.py.
    behave_queue: "asyncio.Queue[tuple[str, Event] | None]" = asyncio.Queue()
    behave_pump_task: asyncio.Task[None] | None = None
    if bus is not None:
        behave_pump_task = asyncio.create_task(
            _behave_pump(bus, behave_queue),
        )

    try:
        while not shutdown.is_set():
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass  # normal tick
            if shutdown.is_set():
                break
            try:
                await _incremental_update(repo, state)
            except Exception as exc:
                logger.error("attacker worker: update failed: %s", exc)
            # BEHAVE-SHELL drain (bus path).
            await _drain_behave_queue(repo, behave_queue, raw_publish)
            # BEHAVE-SHELL poll fallback. Always runs — when bus is up
            # this catches anything the subscription missed during a
            # transient reconnect; when bus is down it's the only path.
            try:
                await _behave_poll_tick(repo, raw_publish)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "attacker worker: behave poll tick failed: %s", exc,
                )
    finally:
        for t in (heartbeat_task, control_task):
            t.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await t
        if behave_pump_task is not None:
            behave_pump_task.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await behave_pump_task
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


@_traced("profiler.incremental_update")
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


_PTR_CONCURRENCY = 10


async def _resolve_ptrs_for(ips: list[str]) -> dict[str, Any]:
    """Resolve PTR for each *ip* concurrently, bounded.

    Returns ``{ip: ptr_or_None}`` for every input. Uses an asyncio
    semaphore to cap parallel lookups — cold-start could see hundreds
    of fresh IPs and we don't want to hammer the OS resolver.
    """
    if not ips:
        return {}
    sem = asyncio.Semaphore(_PTR_CONCURRENCY)

    async def _one(ip: str) -> tuple[str, Any]:
        async with sem:
            return ip, await resolve_ptr_record(ip)

    results = await asyncio.gather(*(_one(ip) for ip in ips))
    return dict(results)


@_traced("profiler.update_profiles")
async def _update_profiles(
    repo: BaseRepository,
    state: _WorkerState,
    ips: set[str],
) -> None:
    traversal_map = {t.attacker_ip: t for t in state.engine.traversals(min_deckies=2)}
    bounties_map = await repo.get_bounties_for_ips(ips)

    # PTR resolution: one shot per IP per worker lifetime. OS resolver
    # caches, so re-runs on worker restart hit cache instantly for IPs
    # resolved recently; only never-seen addresses pay the 2s ceiling.
    fresh = [ip for ip in ips if ip not in state.ptr_attempted]
    for ip in fresh:
        state.ptr_attempted.add(ip)
    ptrs = await _resolve_ptrs_for(fresh)

    _tracer = _get_tracer("profiler")
    for ip in ips:
        events = state.engine._events.get(ip, [])
        if not events:
            continue

        with _tracer.start_as_current_span("profiler.process_ip") as _span:
            _span.set_attribute("attacker_ip", ip)
            _span.set_attribute("event_count", len(events))

            traversal = traversal_map.get(ip)
            bounties = bounties_map.get(ip, [])
            commands = _extract_commands_from_events(events)

            if ip in ptrs:
                record = _build_record(
                    ip, events, traversal, bounties, commands,
                    ptr_record=ptrs[ip],
                )
            else:
                # Not in ptrs → already attempted in a prior cycle → skip
                # kwarg so upsert preserves whatever's stored.
                record = _build_record(ip, events, traversal, bounties, commands)
            attacker_uuid = await repo.upsert_attacker(record)

            # Backfill Credential.attacker_uuid for every credential row
            # captured before the profiler had minted this Attacker. The
            # capture path runs before the profiler — coupling them would
            # create a chicken-and-egg ordering bug. Soft-fail so a backfill
            # error never blocks the next attacker.
            try:
                await repo.update_credential_attacker_uuid(ip, attacker_uuid)
            except Exception as exc:
                _span.record_exception(exc)
                logger.error("attacker worker: credential backfill failed for %s: %s", ip, exc)

            _span.set_attribute("is_traversal", traversal is not None)
            _span.set_attribute("bounty_count", len(bounties))
            _span.set_attribute("command_count", len(commands))

            if state.publish_attacker is not None:
                try:
                    state.publish_attacker("scored", {
                        "attacker_ip": ip,
                        "event_count": record["event_count"],
                        "service_count": record["service_count"],
                        "decky_count": record["decky_count"],
                        "bounty_count": record["bounty_count"],
                        "credential_count": record["credential_count"],
                        "is_traversal": record["is_traversal"],
                    })
                except Exception as exc:
                    logger.warning("attacker worker: scored publish failed for %s: %s", ip, exc)

            # Behavioral / fingerprint rollup lives in a sibling table so failures
            # here never block the core attacker profile upsert.
            try:
                behavior = build_behavior_record(events)
                await repo.upsert_attacker_behavior(attacker_uuid, behavior)
            except Exception as exc:
                _span.record_exception(exc)
                logger.error("attacker worker: behavior upsert failed for %s: %s", ip, exc)

            # SMTP victim-domain tracking — extract domains from RCPT events
            # and upsert one row per (attacker, domain) pair. Same
            # soft-fail posture as the behavior rollup: errors here must
            # not block the next attacker.
            try:
                for domain in _extract_smtp_domains(events):
                    await repo.increment_smtp_target(attacker_uuid, domain)
            except Exception as exc:
                _span.record_exception(exc)
                logger.error("attacker worker: smtp target upsert failed for %s: %s", ip, exc)


_UNSET = object()  # sentinel — distinguishes "not passed" from "None"


def _build_record(
    ip: str,
    events: list[LogEvent],
    traversal: Any,
    bounties: list[dict[str, Any]],
    commands: list[dict[str, Any]],
    *,
    ptr_record: Any = _UNSET,
) -> dict[str, Any]:
    services = sorted({e.service for e in events})
    deckies = (
        traversal.deckies
        if traversal
        else _first_contact_deckies(events)
    )
    fingerprints = [b for b in bounties if b.get("bounty_type") == "fingerprint"]
    credential_count = sum(1 for b in bounties if b.get("bounty_type") == "credential")
    country_code, country_source = enrich_ip(ip)
    asn, as_name, bgp_prefix, asn_source = enrich_ip_asn(ip)

    record: dict[str, Any] = {
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
        "country_code": country_code,
        "country_source": country_source,
        "asn": asn,
        "as_name": as_name,
        "bgp_prefix": bgp_prefix,
        "asn_source": asn_source,
        "updated_at": datetime.now(timezone.utc),
    }
    # ptr_record is omitted from the dict entirely when the caller didn't
    # supply one — lets the upsert's attribute-merge preserve any value
    # already stored on the row without us having to think about "None
    # means preserve vs. overwrite".
    if ptr_record is not _UNSET:
        record["ptr_record"] = ptr_record
    return record


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


_SMTP_ADDR_RE = re.compile(r"<?([^\s<>@]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})>?")


def _normalize_smtp_domain(raw: str) -> str | None:
    """Extract a lowercased domain from an envelope-address fragment.

    Returns None when the input doesn't look like an email address or the
    resulting TLD is on the blocklist. Local-parts (the bit before `@`)
    are intentionally dropped — this table stores no user-identifying
    data, only the targeted organisation's domain.
    """
    if not raw:
        return None
    match = _SMTP_ADDR_RE.search(raw.strip())
    if not match:
        return None
    domain = match.group(2).lower().strip(".")
    if not domain:
        return None
    tld = domain.rsplit(".", 1)[-1]
    if tld in _BLOCKED_TLDS:
        return None
    return domain


def _extract_smtp_domains(events: list[LogEvent]) -> set[str]:
    """Collect the set of victim domains an attacker targeted via SMTP.

    Deduped at the attacker level — repeated hits on the same domain
    within a single batch collapse to one upsert, and the per-row count
    is bumped by ``increment_smtp_target`` on each call. The set return
    type is intentional: we care about *which* domains were seen, not
    the per-batch frequency (which the DB aggregates over time).
    """
    domains: set[str] = set()
    for event in events:
        if event.service != "smtp" or event.event_type not in _SMTP_RCPT_EVENTS:
            continue
        if event.event_type == "message_accepted":
            raw_list = event.fields.get("rcpt_to", "")
            candidates = raw_list.split(",") if raw_list else []
        else:
            candidates = [event.fields.get("value", "")]
        for candidate in candidates:
            domain = _normalize_smtp_domain(candidate)
            if domain:
                domains.add(domain)
    return domains


# ── BEHAVE-SHELL session-ended wiring (Phase 4) ─────────────────────────────


async def _behave_pump(
    bus: BaseBus,
    queue: "asyncio.Queue[tuple[str, Event] | None]",
) -> None:
    """Forward every ``attacker.session.ended`` event into ``queue``.

    Tolerance contract mirrors :func:`decnet.ttp.worker._pump`: the
    subscriber dies → log-and-fall-back-to-poll, never crash the worker
    loop. The poll path (always-on per tick) catches anything missed
    while the subscription is down.
    """
    try:
        sub = bus.subscribe(_BEHAVE_TOPIC)
        async with sub:
            async for event in sub:
                await queue.put((event.topic, event))
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "attacker worker: behave subscriber for %s died (%s); "
            "falling back to poll", _BEHAVE_TOPIC, exc,
        )


async def _drain_behave_queue(
    repo: BaseRepository,
    queue: "asyncio.Queue[tuple[str, Event] | None]",
    publish: Callable[[str, dict[str, Any], str], None] | None,
) -> None:
    """Drain queued ``attacker.session.ended`` events through the
    handler. Each handler invocation is isolated — exceptions log and
    do not block the next event."""
    while not queue.empty():
        item = queue.get_nowait()
        if item is None:
            continue
        _topic, event = item
        try:
            await handle_session_ended(repo, event.payload, publish)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "attacker worker: behave handler raised on bus path: %s", exc,
            )


async def _behave_poll_tick(
    repo: BaseRepository,
    publish: Callable[[str, dict[str, Any], str], None] | None,
) -> None:
    """Poll fallback: scan ``Log`` rows after the saved cursor for
    ``event_type='session_recorded'`` and call the handler for any
    not yet profiled.

    Cursor is stored under :data:`_BEHAVE_POLL_STATE_KEY`, separate from
    the correlation tick's cursor so the two never conflate.
    """
    cursor_state = await repo.get_state(_BEHAVE_POLL_STATE_KEY) or {}
    last_id = int(cursor_state.get("last_log_id", 0))
    rows = await repo.get_logs_after_id(last_id, limit=_BATCH_SIZE)
    if not rows:
        return
    new_cursor = last_id
    for row in rows:
        new_cursor = max(new_cursor, int(row.get("id", 0)))
        if row.get("event_type") != "session_recorded":
            continue
        payload = _payload_from_log_row(row)
        if payload is None:
            continue
        try:
            await handle_session_ended(repo, payload, publish)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "attacker worker: behave handler raised on poll path: %s", exc,
            )
    if new_cursor > last_id:
        await repo.set_state(
            _BEHAVE_POLL_STATE_KEY, {"last_log_id": new_cursor},
        )


def _payload_from_log_row(row: dict[str, Any]) -> dict[str, Any] | None:
    """Project a ``session_recorded`` Log row into the same shape the
    collector publishes on the bus.

    Returns ``None`` when required fields are missing — the handler
    has its own guard, but pre-filtering here avoids the round-trip to
    the handler's logger for malformed rows.
    """
    fields_raw = row.get("fields") or "{}"
    if isinstance(fields_raw, dict):
        fields = fields_raw
    else:
        try:
            fields = json.loads(fields_raw)
        except (ValueError, TypeError):
            return None
    sid = fields.get("sid")
    decky = row.get("decky")
    service = fields.get("service") or row.get("service")
    attacker_ip = row.get("attacker_ip")
    if not (sid and decky and service and attacker_ip):
        return None
    # Resolve shard_path locally — the Log row may not carry one
    # (sessrec.c does not yet emit fields.shard_path).
    shard_path: str | None = None
    try:
        resolved = find_shard_with_sid(str(decky), str(service), str(sid))
    except (ValueError, OSError, PermissionError):
        resolved = None
    if resolved is not None:
        shard_path = str(resolved)
    return {
        "session_id": str(sid),
        "attacker_uuid": None,
        "attacker_ip": str(attacker_ip),
        "decky_id": str(decky),
        "service": str(service),
        "ended_at": row.get("timestamp"),
        "duration_s": fields.get("duration_s"),
        "commands": [],
        "shard_path": shard_path,
    }
