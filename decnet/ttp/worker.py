"""Long-running TTP-tagging worker.

E.3.14 of ``development/TTP_TAGGING.md``. Drains the bus topics
declared in :data:`_TOPICS`, dispatches each event through the
:class:`~decnet.ttp.factory.CompositeTagger`, persists the produced
:class:`~decnet.web.db.models.ttp.TTPTag` rows via
:meth:`BaseRepository.insert_tags`, and publishes the documented
``ttp.tagged`` + ``ttp.rule.fired.<technique_id>`` events — but
*only* when ``insert_tags`` reported a non-zero rowcount, per the
"loop-prevention invariant" in TTP_TAGGING.md §"Bus topics".

Bus subscriptions are enumerated as the module-level constant
:data:`_TOPICS` so E.2.12 can assert subscription wiring without
invoking the loop. The constant is the *single source of truth* —
the loop iterates over it; tests introspect it.

The inner loop drains a shared ``asyncio.Queue`` populated by one
task per topic. Each queued item is a ``(topic, Event)`` pair —
the topic decides the lifter family (and therefore the
``source_kind``), the payload carries the per-event identifiers.
Bus loss is tolerated: on transport error the per-topic pump task
exits and the loop falls back to the poll interval, which still
heartbeats and accepts a clean shutdown.
"""
from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, Optional

from decnet import telemetry as _telemetry
from decnet.bus import topics as _topics
from decnet.bus.base import BaseBus, Event
from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    run_control_listener_signal as _run_control_listener_signal,
    run_health_heartbeat as _run_health_heartbeat,
)
from decnet.logging import get_logger
from decnet.ttp.base import Tagger, TaggerEvent
from decnet.ttp.factory import CompositeTagger, get_tagger
from decnet.web.db.models.ttp import TTPTag
from decnet.web.db.repository import BaseRepository

log = get_logger("ttp.worker")

_DEFAULT_POLL_SECS = 60.0


# Bus topics the worker subscribes to. Kept as a module-level constant
# so E.2.12 can assert subscription wiring without invoking the loop —
# the test introspects this tuple, the loop iterates it. The set
# matches the design doc "Worker shape" section: session-ended primary
# trigger, observed for low-latency rules, intel-enriched + identity
# events for opportunistic re-tag, credential-reuse + email for the
# dedicated lifters, and ``canary.>`` for fleet-wide canary triggers.
_TOPICS: tuple[str, ...] = (
    _topics.attacker(_topics.ATTACKER_SESSION_ENDED),
    _topics.attacker(_topics.ATTACKER_OBSERVED),
    _topics.attacker(_topics.ATTACKER_INTEL_ENRICHED),
    # attacker.fingerprinted carries JARM/HASSH/tcpfp/ipv6_leak results from
    # the prober and sniffer. Event.type discriminates the kind; lifters that
    # don't recognise the source_kind derived from Event.type are no-ops.
    _topics.attacker(_topics.ATTACKER_FINGERPRINTED),
    _topics.identity(_topics.IDENTITY_FORMED),
    _topics.identity(_topics.IDENTITY_MERGED),
    _topics.credential(_topics.CREDENTIAL_REUSE_DETECTED),
    _topics.email_topic(_topics.EMAIL_RECEIVED),
    # Canary triggers carry a per-token segment, so subscribe with the
    # multi-token wildcard rather than enumerating per-token. Pattern
    # validated against ``decnet.bus.topics.canary()``'s shape.
    f"{_topics.CANARY}.>",
)


# Topic-segment → ``source_kind`` for the resulting TaggerEvent. We
# match on a short token contained in the topic so wildcard topics
# (``canary.{id}.triggered``) and per-event topics work uniformly.
_TOPIC_SOURCE_KIND: tuple[tuple[str, str], ...] = (
    ("session.ended", "session"),
    ("observed", "session"),
    ("intel.enriched", "intel"),
    ("identity.formed", "identity"),
    ("identity.merged", "identity"),
    ("reuse.detected", "credential"),
    ("email.received", "email"),
    ("canary.", "canary_fingerprint"),
)


def _source_kind_for(topic: str) -> str | None:
    for fragment, kind in _TOPIC_SOURCE_KIND:
        if fragment in topic:
            return kind
    return None


@contextmanager
def _span(name: str, **attrs: Any) -> Iterator[Any]:
    """Tracing helper short-circuiting on ``DECNET_DEVELOPER_TRACING``.

    Same shape as the engine / store helpers — single attribute lookup
    when off, late-bound tracer when on so test monkeypatches reach us.
    """
    if not _telemetry._ENABLED:
        yield None
        return
    tracer = _telemetry.get_tracer("ttp.worker")
    with tracer.start_as_current_span(name) as span:
        for key, value in attrs.items():
            try:
                span.set_attribute(key, value)
            except (TypeError, ValueError):
                continue
        yield span


def _build_events(
    topic: str, payload: dict[str, Any], event_type: str = "",
) -> list[TaggerEvent]:
    """Translate one bus payload into one OR MORE :class:`TaggerEvent`s.

    A single ``attacker.session.ended`` event carries a *bag* of commands
    issued during that session. The R0001–R0030 rule pack matches per
    command, not per session, so we fan the session payload out into
    one ``source_kind="command"`` event per command (in addition to the
    session-level event itself for behavioral / cross-event rules).

    The session event still fires; lifters that key on
    ``source_kind="session"`` (e.g. :class:`BehavioralLifter`) see it.
    Lifters keyed on ``source_kind="command"`` (the
    :class:`RuleEngineTagger` shell-rule path) see one event per
    command. Idempotent inserts keep duplicate emits safe.

    Recognized payload shapes for the per-command fan-out:

    * ``commands: list[str]`` — bare command strings.
    * ``commands: list[{"command_text": str, "id": str?, ...}]`` — dicts
      with at least a ``command_text`` field; any ``id`` / ``uuid`` /
      ``command_id`` becomes the ``source_id`` for idempotency.

    *event_type* is forwarded from ``Event.type``; used by multiplex
    topics (``attacker.fingerprinted``) where the kind discriminator lives
    in the envelope rather than the topic path.
    """
    base = _build_event(topic, payload, event_type=event_type)
    if base is None:
        return []
    out = [base]
    if base.source_kind != "session":
        return out
    commands = payload.get("commands")
    if not isinstance(commands, list):
        return out
    for idx, cmd in enumerate(commands):
        cmd_event = _build_command_event(base, cmd, idx)
        if cmd_event is not None:
            out.append(cmd_event)
    return out


def _build_command_event(
    base: TaggerEvent, cmd: Any, idx: int,
) -> TaggerEvent | None:
    if isinstance(cmd, str):
        text = cmd
        cmd_id = f"{base.source_id}#cmd{idx}"
        cmd_payload: dict[str, Any] = {"command_text": text}
    elif isinstance(cmd, dict):
        text_obj = cmd.get("command_text") or cmd.get("text")
        if not isinstance(text_obj, str):
            return None
        cmd_id_obj = (
            cmd.get("id")
            or cmd.get("uuid")
            or cmd.get("command_id")
            or f"{base.source_id}#cmd{idx}"
        )
        cmd_id = str(cmd_id_obj)
        cmd_payload = {**cmd, "command_text": text_obj}
    else:
        return None
    return TaggerEvent(
        source_kind="command",
        source_id=cmd_id,
        attacker_uuid=base.attacker_uuid,
        identity_uuid=base.identity_uuid,
        session_id=base.session_id,
        decky_id=base.decky_id,
        payload=cmd_payload,
    )


def _build_event(
    topic: str, payload: dict[str, Any], event_type: str = "",
) -> TaggerEvent | None:
    """Translate one bus payload into a :class:`TaggerEvent`.

    Returns ``None`` if the topic isn't one we know how to dispatch
    (defensive — :data:`_TOPICS` and :data:`_TOPIC_SOURCE_KIND` are
    kept in sync, but a wildcard subscription could in theory deliver
    a topic outside the table).

    ``source_id`` is the stable per-event identifier the repository
    uses for idempotency. We prefer the most-specific ID present in
    the payload so a replay of the same upstream event produces the
    same :func:`compute_tag_uuid` and the ``INSERT OR IGNORE`` write
    becomes a no-op the second time around. The order below is the
    same priority list the lifters use internally.

    *event_type* is used as ``source_kind`` when ``_source_kind_for``
    has no static mapping for *topic* — this covers multiplex topics
    such as ``attacker.fingerprinted`` where the kind discriminator is
    carried in ``Event.type`` rather than the topic path itself.
    """
    source_kind = _source_kind_for(topic)
    if source_kind is None:
        if event_type:
            source_kind = event_type
        else:
            return None
    source_id = (
        payload.get("source_id")
        or payload.get("session_id")
        or payload.get("token_id")
        or payload.get("identity_uuid")
        or payload.get("credential_id")
        or payload.get("attacker_uuid")
        or payload.get("uuid")
        or topic
    )
    return TaggerEvent(
        source_kind=source_kind,
        source_id=str(source_id),
        attacker_uuid=_str_or_none(payload.get("attacker_uuid")),
        identity_uuid=_str_or_none(payload.get("identity_uuid")),
        session_id=_str_or_none(payload.get("session_id")),
        decky_id=_str_or_none(payload.get("decky_id")),
        payload=dict(payload),
    )


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


async def _build_intel_catchup_event(
    repo: "BaseRepository",
    base: TaggerEvent,
) -> TaggerEvent | None:
    """Synthesize an intel TaggerEvent from the persisted AttackerIntel row.

    Called on every ``attacker.session.ended`` so intel-derived tags emit
    even when ``attacker.intel.enriched`` was dropped or arrived before the
    TTP worker started. Per the no-SPOF contract (TTP_TAGGING.md lines
    212–219) we import ``AttackerIntel`` (a data shape) but never any
    ``decnet.intel.*`` provider client.

    Returns ``None`` when no intel row exists for the attacker (the normal
    case for a freshly-observed attacker) or when the lookup fails.
    """
    if base.attacker_uuid is None:
        return None
    with _span(
        "ttp.worker.intel_catchup",
        attacker_uuid=base.attacker_uuid,
    ):
        try:
            row = await repo.get_attacker_intel_row_by_uuid(base.attacker_uuid)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "ttp worker: intel catch-up lookup failed for "
                "attacker_uuid=%r: %s",
                base.attacker_uuid, exc,
            )
            return None
        if row is None:
            return None
        payload = row.to_intel_event_payload()
    source_id = f"intel-catchup:{base.session_id or base.attacker_uuid}"
    return TaggerEvent(
        source_kind="intel",
        source_id=source_id,
        attacker_uuid=base.attacker_uuid,
        identity_uuid=base.identity_uuid,
        session_id=base.session_id,
        decky_id=base.decky_id,
        payload=payload,
    )


async def run_ttp_worker_loop(
    repo: BaseRepository,
    *,
    poll_interval_secs: float = _DEFAULT_POLL_SECS,
    tagger: Optional[Tagger] = None,
    shutdown: Optional[asyncio.Event] = None,
    bus: Optional[BaseBus] = None,
) -> None:
    """Run the TTP-tagging loop until cancelled.

    *tagger* defaults to :func:`decnet.ttp.factory.get_tagger`; tests
    pass a fake. *shutdown* is an optional external stop signal; the
    loop also exits cleanly on :class:`asyncio.CancelledError` and
    :class:`KeyboardInterrupt`. *bus* is an optional pre-wired bus;
    when omitted the worker calls :func:`get_bus` itself, falling back
    to poll-only when the bus is unavailable (typical dev box without
    a NATS daemon).
    """
    if tagger is None:
        tagger = get_tagger()

    # Fail closed at boot if any technique/tactic the worker can emit
    # is missing from the loaded ATT&CK STIX bundle. The bundle is the
    # canonical source of truth (see decnet/ttp/attack_stix.py) — drift
    # between the pinned version and what the lifters reference would
    # silently mistag thousands of events. We run this once per worker
    # process; the underlying bundle load is itself memoised.
    from decnet.clustering.ukc import validate_against_attack_bundle as _validate_ukc
    from decnet.ttp.impl.intel_lifter import (
        validate_against_attack_bundle as _validate_intel,
    )

    _validate_intel()
    _validate_ukc()

    log.info(
        "ttp worker started tagger=%s poll_interval_secs=%s topics=%d",
        tagger.name, poll_interval_secs, len(_TOPICS),
    )

    owned_bus = False
    queue: asyncio.Queue[tuple[str, Event] | None] = asyncio.Queue()
    pump_tasks: list[asyncio.Task[None]] = []
    watch_tasks: list[asyncio.Task[None]] = []
    heartbeat_task: Optional[asyncio.Task[None]] = None
    control_task: Optional[asyncio.Task[None]] = None

    # Hydrate per-lifter rule indexes. Each WatchableTagger
    # (CompositeTagger children + the RuleEngineTagger) owns its own
    # RuleIndex and drains store change events forever via
    # `watch_store`. Without these tasks every dispatch index stays
    # empty and no rule fires — the bus subscriptions work, the
    # pump tasks run, and tagger.tag() returns [] every call. Tasks
    # are independent of the bus, so this fan-out runs even in
    # poll-only mode.
    if isinstance(tagger, CompositeTagger):
        for watchable in tagger.iter_watchables():
            watch_tasks.append(asyncio.create_task(
                _run_watch(watchable),
            ))
    try:
        if bus is None:
            try:
                candidate = get_bus(client_name="ttp")
                await candidate.connect()
                bus = candidate
                owned_bus = True
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "ttp worker: bus unavailable, running in poll-only mode: %s",
                    exc,
                )
                bus = None
        if bus is not None:
            for pattern in _TOPICS:
                pump_tasks.append(asyncio.create_task(
                    _pump(bus, queue, pattern),
                ))
            heartbeat_task = asyncio.create_task(
                _run_health_heartbeat(bus, "ttp"),
            )
            control_task = asyncio.create_task(
                _run_control_listener_signal(bus, "ttp"),
            )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "ttp worker: bus setup failed, running in poll-only mode: %s", exc,
        )

    if shutdown is None:
        shutdown = asyncio.Event()

    try:
        while not shutdown.is_set():
            try:
                item = await asyncio.wait_for(
                    queue.get(), timeout=float(poll_interval_secs),
                )
            except asyncio.TimeoutError:
                continue
            if item is None:
                continue
            topic, event = item
            await _process_event(topic, event, tagger, repo, bus)
    except (asyncio.CancelledError, KeyboardInterrupt):
        log.info("ttp worker stopped")
    finally:
        for task in pump_tasks:
            task.cancel()
        for task in watch_tasks:
            task.cancel()
        if heartbeat_task is not None:
            heartbeat_task.cancel()
        if control_task is not None:
            control_task.cancel()
        for task in pump_tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        for task in watch_tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        for opt in (heartbeat_task, control_task):
            if opt is None:
                continue
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await opt
        if owned_bus and bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


async def _resolve_attacker_uuid(
    repo: BaseRepository, payload: dict[str, Any],
) -> dict[str, Any] | None:
    """Inject ``attacker_uuid`` into *payload* via repo lookup if missing.

    Collector-side producers (notably ``attacker.session.ended`` from
    the session aggregator) carry ``attacker_ip`` but cannot fill
    ``attacker_uuid`` because the collector doesn't talk to the DB.
    The TTP worker resolves it here so ``compute_tag_uuid`` and the
    ``ttp_tag_has_anchor`` model invariant always have something to
    work with.

    Returns the (possibly mutated) payload, or ``None`` if neither
    ``attacker_uuid`` nor ``identity_uuid`` could be set — emitting a
    tag with both NULL would raise inside :class:`TTPTag.__init__`.
    """
    if payload.get("attacker_uuid") or payload.get("identity_uuid"):
        return payload
    ip = payload.get("attacker_ip")
    if not isinstance(ip, str) or not ip or ip == "Unknown":
        log.debug(
            "ttp worker: dropping event with no anchor "
            "(no attacker_uuid / identity_uuid / attacker_ip)",
        )
        return None
    try:
        resolved = await repo.get_attacker_uuid_by_ip(ip)
    except Exception:  # noqa: BLE001
        log.exception(
            "ttp worker: get_attacker_uuid_by_ip(%r) failed", ip,
        )
        return None
    if not resolved:
        log.info(
            "ttp worker: no Attacker row for ip=%r yet; "
            "skipping until profiler catches up", ip,
        )
        return None
    return {**payload, "attacker_uuid": resolved}


async def _process_event(
    topic: str,
    event: Event,
    tagger: Tagger,
    repo: BaseRepository,
    bus: BaseBus | None,
) -> None:
    """Dispatch one event through the tagger, persist, publish if new.

    Loop-prevention invariant: ``ttp.tagged`` is published ONLY when
    :meth:`BaseRepository.insert_tags` returned a non-zero count. A
    replay of the same upstream event hits the idempotent
    ``INSERT OR IGNORE`` and writes zero rows → publishes zero events.
    """
    payload = await _resolve_attacker_uuid(repo, event.payload)
    if payload is None:
        # Both attacker_uuid and identity_uuid are missing and we
        # couldn't resolve from attacker_ip — the TTPTag invariant
        # requires at least one anchor, so emitting any tag would
        # raise. Drop the event with one log line per cold IP.
        return
    tagger_events = _build_events(topic, payload, event_type=event.type)
    if not tagger_events:
        return
    # Intel catch-up: on session.ended, read the persisted intel row (if
    # any) and append an intel TaggerEvent so intel-derived tags emit even
    # when attacker.intel.enriched was dropped or arrived before the worker
    # started. Idempotent UUIDs deduplicate against any prior intel.enriched
    # path. No-intel-row case is silent (freshly-observed attacker).
    if "session.ended" in topic:
        intel_event = await _build_intel_catchup_event(repo, tagger_events[0])
        if intel_event is not None:
            tagger_events.append(intel_event)
    # Aggregate tags across the session-level event AND any per-command
    # fan-out so the bus publish sees a single ttp.tagged envelope per
    # upstream session. The repository's INSERT OR IGNORE keeps replay
    # idempotent across the entire batch.
    all_tags: list[TTPTag] = []
    for tagger_event in tagger_events:
        with _span(
            "ttp.worker.tick",
            topic=topic,
            source_kind=tagger_event.source_kind,
        ):
            try:
                tags = await tagger.tag(tagger_event)
            except Exception:  # noqa: BLE001
                # Composite + TolerantTagger normally swallow per-lifter
                # blow-ups already; this is the worst-case backstop so a
                # single bad event can't take down the whole loop.
                log.exception(
                    "ttp worker: tagger raised on topic=%r source_kind=%r",
                    topic, tagger_event.source_kind,
                )
                continue
            all_tags.extend(tags)
    if not all_tags:
        return
    try:
        inserted = await repo.insert_tags(all_tags)
    except Exception:  # noqa: BLE001
        log.exception(
            "ttp worker: insert_tags failed on topic=%r", topic,
        )
        return
    if inserted <= 0:
        # Idempotent re-eval — the loop-prevention invariant
        # forbids publishing here.
        return
    await _bump_ipv6_leak_denorm(repo, all_tags)
    if bus is not None:
        await _publish_tagged(bus, all_tags)


async def _bump_ipv6_leak_denorm(
    repo: BaseRepository, tags: list[TTPTag],
) -> None:
    """Update Attacker / AttackerIdentity denorm columns for ipv6_leak tags.

    Called once per successful insert_tags batch. Takes the first tag
    per attacker_uuid (all tags in a batch share the same attacker context).
    Silently skips if the repo method is unavailable (pre-migration DBs).
    """
    ipv6_tags = [t for t in tags if t.source_kind == "ipv6_leak"]
    if not ipv6_tags:
        return
    seen: set[str] = set()
    for tag in ipv6_tags:
        if tag.attacker_uuid is None or tag.attacker_uuid in seen:
            continue
        seen.add(tag.attacker_uuid)
        try:
            await repo.bump_attacker_ipv6_leak(
                attacker_uuid=tag.attacker_uuid,
                identity_uuid=tag.identity_uuid,
                evidence=tag.evidence or {},
            )
        except Exception:  # noqa: BLE001
            log.warning(
                "ttp worker: bump_attacker_ipv6_leak failed for "
                "attacker_uuid=%r", tag.attacker_uuid,
            )


async def _publish_tagged(bus: BaseBus, tags: list[TTPTag]) -> None:
    """Publish ``ttp.tagged`` + per-technique ``ttp.rule.fired.*``.

    ``ttp.tagged`` carries the deduped technique list so a SIEM
    subscriber can correlate without a DB read; per-technique fires
    are 1:1 with the technique IDs touched by this batch (deduped so
    a single batch produces one ``ttp.rule.fired.T1110`` even if
    three rules emitted T1110).
    """
    if not tags:
        return
    techniques = sorted({t.technique_id for t in tags})
    aggregate_payload: dict[str, Any] = {
        "attacker_uuid": tags[0].attacker_uuid,
        "identity_uuid": tags[0].identity_uuid,
        "session_id": tags[0].session_id,
        "tag_uuids": [t.uuid for t in tags],
        "techniques_added": techniques,
    }
    await bus.publish(
        _topics.ttp(_topics.TTP_TAGGED),
        aggregate_payload,
        event_type=_topics.TTP_TAGGED,
    )
    for technique_id in techniques:
        per_tech_payload: dict[str, Any] = {
            "technique_id": technique_id,
            "tag_uuids": [t.uuid for t in tags if t.technique_id == technique_id],
            "attacker_uuid": tags[0].attacker_uuid,
            "identity_uuid": tags[0].identity_uuid,
            "session_id": tags[0].session_id,
        }
        await bus.publish(
            _topics.ttp_rule_fired(technique_id),
            per_tech_payload,
            event_type=_topics.TTP_RULE_FIRED,
        )


async def _run_watch(watchable: Any) -> None:
    """Drive one lifter's ``watch_store()`` coroutine forever.

    Mirrors :func:`_pump`'s tolerance contract: a transient store error
    logs and exits the watch task without taking the worker down. The
    main loop's poll-interval fallback continues to heartbeat; a
    subsequent worker restart re-runs the watch fan-out and rehydrates.
    """
    name = getattr(watchable, "name", watchable.__class__.__name__)
    try:
        await watchable.watch_store()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "ttp worker: watch_store for %s died (%s); index will not "
            "hot-reload until next worker restart", name, exc,
        )


async def _pump(
    bus: BaseBus,
    queue: "asyncio.Queue[tuple[str, Event] | None]",
    pattern: str,
) -> None:
    """Forward every event matching *pattern* into *queue*.

    Survives transient subscriber errors by logging and exiting; the
    poll-interval fallback in the main loop keeps the worker alive
    until the next reconnect attempt.
    """
    try:
        sub = bus.subscribe(pattern)
        async with sub:
            async for event in sub:
                await queue.put((event.topic, event))
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "ttp worker: subscriber for %s died (%s); falling back to poll",
            pattern, exc,
        )


__all__ = ["run_ttp_worker_loop", "_TOPICS"]
