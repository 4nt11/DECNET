"""Orchestrator main loop.

One tick = one action pick + one driver invocation + one DB write +
one fire-and-forget bus publish.  Intentionally serial — MVP honesty:
a wedged docker exec stalls only this worker, never another.

Three action shapes are folded into the single tick after stage 5 of
the realism migration: SSH traffic between deckies, file plants on
deckies (driven by :func:`decnet.realism.planner.pick`), and email
drops into mail-decky maildirs (driven by
:func:`decnet.orchestrator.emailgen.scheduler.pick`).  ``decnet
emailgen`` and ``decnet-emailgen.service`` are gone; this worker
covers all three.

Modeled after :mod:`decnet.profiler.worker` for consistency: same
control listener, same heartbeat helper, same shutdown semantics.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Optional

from decnet.bus.factory import get_bus
from decnet.bus.publish import (
    publish_safely,
    run_control_listener,
    run_health_heartbeat,
)
from decnet.logging import get_logger
from decnet.orchestrator import events, scheduler
from decnet.orchestrator.drivers import get_driver_for
from decnet.orchestrator.emailgen import (
    events as email_events,
    scheduler as email_scheduler,
)
from decnet.orchestrator.emailgen.scheduler import EmailAction
from decnet.realism import planner as realism_planner
from decnet.realism.llm.circuit import LLMCircuitBreaker
from decnet.web.db.repository import BaseRepository

logger = get_logger("orchestrator")

# Periodic-prune knobs. Trim per-decky history every _PRUNE_EVERY_TICKS
# to keep orchestrator_events / orchestrator_emails from unbounded
# growth on long-running fleets. Cheap on the write path (zero overhead
# per tick); the cost pays in once every ~100 ticks.
_PRUNE_EVERY_TICKS = 100
_PRUNE_PER_DST_CAP = 10000
_PRUNE_PER_MAIL_DECKY_CAP = 5000

# Refresh planner weights from realism_config every N ticks. Operator
# tunables drift slowly; ~minute-scale latency between PUT and effect
# is fine. No bus signal — keeps the path simple and the orchestrator
# self-contained.
_REALISM_CONFIG_REFRESH_TICKS = 5

# Action-kind weights for the per-tick roll.  Email is rare because
# each LLM round-trip is expensive (~seconds) and the prior emailgen
# worker only ticked every 5 minutes.  At a 60s orchestrator interval,
# a 10% email weight produces ~one email every ~10 minutes — close
# enough to the pre-collapse cadence.
_ACTION_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("traffic", 45),
    ("file", 45),
    ("email", 10),
)


async def orchestrator_worker(
    repo: BaseRepository,
    *,
    interval: int = 60,
    llm_enabled: Optional[bool] = None,
) -> None:
    """Periodically inject synthetic activity into the running fleet.

    Runs as a long-lived asyncio task.  Honours the bus control topic
    (``system.orchestrator.control``) for graceful shutdown.

    LLM enrichment for user-class file bodies is opt-in via the
    ``DECNET_REALISM_LLM`` env var (set to ``ollama`` / ``fake`` /
    empty).  Pass ``llm_enabled=False`` from the CLI to override
    (``decnet orchestrate --no-llm``).  When the LLM is unreachable
    or wedged, a process-local circuit breaker
    (:class:`LLMCircuitBreaker`) trips after 3 consecutive failures
    and the worker falls back to deterministic templates for 60
    seconds before re-probing.
    """
    logger.info("orchestrator worker started interval=%ds", interval)

    llm: Any = None
    breaker: Optional[LLMCircuitBreaker] = None
    if _llm_should_enable(llm_enabled):
        try:
            from decnet.realism.llm import get_llm
            llm = get_llm()
            breaker = LLMCircuitBreaker()
            logger.info(
                "orchestrator: LLM enrichment enabled backend=%s model=%s",
                os.environ.get("DECNET_REALISM_LLM", "ollama"),
                getattr(llm, "model", "?"),
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "orchestrator: LLM init failed, continuing without "
                "enrichment: %s", exc,
            )
            llm = None

    bus = None
    try:
        bus = get_bus(client_name="orchestrator")
        await bus.connect()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "orchestrator: bus unavailable, continuing without publish: %s", exc
        )
        bus = None

    # Initial load — pulls the operator-tuned weights from
    # realism_config so the orchestrator starts ticking with the
    # operator's intent rather than the baked-in defaults. A failure
    # here logs and falls through; the planner already holds defaults.
    await _refresh_realism_config(repo)

    shutdown = asyncio.Event()
    heartbeat_task = asyncio.create_task(
        run_health_heartbeat(
            bus, "orchestrator",
            extra=lambda: {"realism": _realism_health_snapshot(llm, breaker)},
        )
    )
    control_task = asyncio.create_task(
        run_control_listener(bus, "orchestrator", shutdown),
    )
    tick_n = 0
    try:
        while not shutdown.is_set():
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass  # normal tick
            if shutdown.is_set():
                break
            try:
                await _one_tick(repo, bus, llm=llm, breaker=breaker)
            except Exception as exc:  # noqa: BLE001
                logger.error("orchestrator tick failed: %s", exc)
            tick_n += 1
            if tick_n % _PRUNE_EVERY_TICKS == 0:
                await _periodic_prune(repo)
            if tick_n % _REALISM_CONFIG_REFRESH_TICKS == 0:
                await _refresh_realism_config(repo)
    finally:
        for t in (heartbeat_task, control_task):
            t.cancel()
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await t
        if bus is not None:
            with contextlib.suppress(Exception):
                await bus.close()


async def _periodic_prune(repo: BaseRepository) -> None:
    try:
        deleted = await repo.prune_orchestrator_events(per_dst_cap=_PRUNE_PER_DST_CAP)
        if deleted:
            logger.info(
                "orchestrator events prune deleted=%d cap=%d",
                deleted, _PRUNE_PER_DST_CAP,
            )
    except Exception as exc:  # noqa: BLE001
        logger.error("orchestrator events prune failed: %s", exc)
    try:
        deleted = await repo.prune_orchestrator_emails(
            per_decky_cap=_PRUNE_PER_MAIL_DECKY_CAP,
        )
        if deleted:
            logger.info(
                "orchestrator emails prune deleted=%d cap=%d",
                deleted, _PRUNE_PER_MAIL_DECKY_CAP,
            )
    except Exception as exc:  # noqa: BLE001
        logger.error("orchestrator emails prune failed: %s", exc)


async def _refresh_realism_config(repo: BaseRepository) -> None:
    """Pull operator-tuned weights from realism_config into the planner.

    Failure modes (DB unreachable, malformed JSON, validation reject)
    log and leave the planner's current weights in place. The orchestrator
    keeps ticking with whatever it had — never blocks on config.
    """
    try:
        row = await repo.get_realism_config("weights")
    except Exception as exc:  # noqa: BLE001
        logger.warning("realism config refresh: DB read failed: %s", exc)
        return
    if row is None:
        return  # no overrides set; defaults stand
    import json
    try:
        payload = json.loads(row.get("value") or "{}")
    except json.JSONDecodeError as exc:
        logger.warning("realism config refresh: malformed JSON: %s", exc)
        return
    if not isinstance(payload, dict):
        logger.warning("realism config refresh: payload not an object")
        return
    try:
        realism_planner.apply_payload(payload)
    except ValueError as exc:
        logger.warning("realism config refresh: rejected payload: %s", exc)


def _roll_action_kind(rng: secrets.SystemRandom) -> str:
    total = sum(w for _, w in _ACTION_WEIGHTS)
    target = rng.randint(1, total)
    running = 0
    for kind, w in _ACTION_WEIGHTS:
        running += w
        if target <= running:
            return kind
    return _ACTION_WEIGHTS[-1][0]  # unreachable, satisfy mypy


def _realism_health_snapshot(
    llm: Any, breaker: Optional[LLMCircuitBreaker],
) -> dict[str, Any]:
    """Snapshot of the orchestrator's realism subsystem for the
    heartbeat ``extra`` payload.

    Surfaces the LLM backend / model / circuit-breaker state so the
    dashboard can render a status badge without reaching into worker
    process memory. Read-only — the heartbeat ticks every 30s; this
    snapshot is recomputed each tick.

    When LLM is disabled (``llm is None``) the snapshot still
    returns a dict so consumers can branch on ``llm_enabled`` alone.
    """
    if llm is None:
        return {
            "llm_enabled": False,
            "llm_backend": None,
            "llm_model": None,
            "llm_breaker_state": None,
        }
    return {
        "llm_enabled": True,
        "llm_backend": os.environ.get("DECNET_REALISM_LLM", "ollama"),
        "llm_model": getattr(llm, "model", None),
        "llm_breaker_state": breaker.state if breaker is not None else None,
    }


def _llm_should_enable(explicit: Optional[bool]) -> bool:
    """Resolve the LLM-enabled flag from CLI / env / defaults.

    *explicit* takes precedence (``--llm`` / ``--no-llm``).  When unset,
    the env var ``DECNET_REALISM_LLM`` decides: any non-empty value
    (``ollama`` / ``fake`` / etc.) enables; empty string or ``off`` /
    ``none`` / ``0`` / ``false`` disables.
    """
    if explicit is not None:
        return explicit
    raw = os.environ.get("DECNET_REALISM_LLM", "").strip().lower()
    if raw in ("", "off", "none", "0", "false", "disabled"):
        return False
    return True


async def _pick_action(
    repo: BaseRepository,
    deckies: list[dict],
    rng: secrets.SystemRandom,
    *,
    llm: Any = None,
    breaker: Optional[LLMCircuitBreaker] = None,
):
    """Roll an action-kind, then pick the matching action.

    Quiet branches fall through to the other two so a (decky-set,
    persona-pool, mail-decky) shape that would silence one branch
    doesn't waste the whole tick.
    """
    kinds_in_priority_order = [_roll_action_kind(rng)]
    for kind, _ in _ACTION_WEIGHTS:
        if kind not in kinds_in_priority_order:
            kinds_in_priority_order.append(kind)

    for kind in kinds_in_priority_order:
        if kind == "traffic":
            action = scheduler.pick(deckies, rand=rng)
        elif kind == "file":
            action = await scheduler.pick_file(
                deckies, repo, rand=rng,
                llm=llm, llm_breaker=breaker,
            )
        elif kind == "email":
            try:
                action = await email_scheduler.pick(repo, rand=rng)
            except Exception as exc:  # noqa: BLE001
                logger.debug("orchestrator: email pick failed: %s", exc)
                action = None
        else:
            action = None
        if action is not None:
            return action
    return None


async def _one_tick(
    repo: BaseRepository,
    bus,
    *,
    llm: Any = None,
    breaker: Optional[LLMCircuitBreaker] = None,
) -> None:
    deckies = await repo.list_running_deckies()
    rng = secrets.SystemRandom()

    action = await _pick_action(repo, deckies, rng, llm=llm, breaker=breaker)
    if action is None:
        ssh_eligible = sum(
            1 for d in deckies
            if isinstance(d.get("services"), list)
            and "ssh" in d["services"]
            and d.get("ip")
        )
        by_source: dict[str, int] = {}
        for d in deckies:
            src = d.get("source", "unknown")
            by_source[src] = by_source.get(src, 0) + 1
        logger.debug(
            "orchestrator: no actionable deckies "
            "(running=%d ssh_eligible=%d sources=%s)",
            len(deckies), ssh_eligible, by_source,
        )
        return

    driver = get_driver_for(action)
    result = await driver.run(action)

    if isinstance(action, EmailAction):
        await _persist_email(repo, action, result, bus)
    else:
        await _persist_event(repo, action, result, bus)
        if result.success:
            if isinstance(action, scheduler.FileAction):
                try:
                    await _record_synthetic_file(repo, action)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "orchestrator: synthetic_files write failed dst=%s path=%s: %s",
                        action.dst_uuid, action.path, exc,
                    )
            elif isinstance(action, scheduler.EditAction):
                try:
                    await _bump_synthetic_file_after_edit(repo, action, result)
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "orchestrator: synthetic_files edit-bump failed "
                        "dst=%s path=%s: %s",
                        action.dst_uuid, action.path, exc,
                    )


async def _persist_event(repo, action, result, bus) -> None:
    row = events.to_row(action, result)
    await repo.record_orchestrator_event(row)

    if bus is not None:
        topic = events.topic_for(action)
        bus_payload = {
            "kind": row["kind"],
            "protocol": row["protocol"],
            "action": row["action"],
            "src_decky_uuid": row.get("src_decky_uuid"),
            "dst_decky_uuid": row["dst_decky_uuid"],
            "success": row["success"],
            "payload": result.payload,
            "ts": row["ts"].isoformat(),
        }
        await publish_safely(
            bus, topic, bus_payload, event_type=events.event_type_for(action),
        )

    logger.info(
        "orchestrator tick kind=%s success=%s dst=%s",
        row["kind"], row["success"], row["dst_decky_uuid"],
    )


async def _persist_email(repo, action: EmailAction, result, bus) -> None:
    """Persist + publish an email tick result.

    Mirrors the pre-collapse emailgen worker payload exactly so SSE
    subscribers and dashboards keep working without a breaking change
    to the on-the-wire shape.
    """
    row = email_events.to_row(action, result)
    await repo.record_orchestrator_email(row)

    if bus is not None:
        topic = email_events.topic_for(action)
        bus_payload = {
            "kind": "email",
            "mail_decky_uuid": row["mail_decky_uuid"],
            "thread_id": row["thread_id"],
            "message_id": row["message_id"],
            "in_reply_to": row["in_reply_to"],
            "sender_email": row["sender_email"],
            "recipient_email": row["recipient_email"],
            "subject": row["subject"],
            "language": row["language"],
            "success": row["success"],
            "ts": row["ts"].isoformat(),
        }
        await publish_safely(
            bus, topic, bus_payload,
            event_type=email_events.event_type_for(action),
        )

    logger.info(
        "orchestrator tick kind=email mail_decky=%s thread=%s success=%s reply=%s",
        row["mail_decky_uuid"], row["thread_id"], row["success"], action.is_reply,
    )


async def _bump_synthetic_file_after_edit(repo, action, result) -> None:
    """Patch ``synthetic_files`` after a successful EditAction.

    Bumps ``edit_count`` + ``last_modified`` + ``content_hash`` so the
    dashboard's lineage view shows the change.  When the row's UUID
    isn't on the action (planner produced an edit plan from a stale
    candidate that the repo pruned in between), the update is a no-op
    — resurrecting a pruned row isn't this layer's job.

    The new body comes from ``result.payload["new_body"]`` (the SSH
    driver stashes it on success); we re-hash here so the orchestrator,
    not the driver, owns the canonical hash field.
    """
    if not action.synthetic_file_uuid:
        return
    new_body = result.payload.get("new_body", "")
    rows = await repo.list_synthetic_files(decky_uuid=action.dst_uuid, limit=200)
    existing = next(
        (r for r in rows if r.get("uuid") == action.synthetic_file_uuid),
        None,
    )
    if existing is None:
        return  # candidate was pruned mid-flight; skip silently
    patch: dict = {
        "last_modified": datetime.now(timezone.utc),
        "edit_count": int(existing.get("edit_count", 0)) + 1,
    }
    if new_body:
        patch["content_hash"] = hashlib.sha256(
            new_body.encode("utf-8"),
        ).hexdigest()
        patch["last_body"] = new_body
    await repo.update_synthetic_file(action.synthetic_file_uuid, patch)


async def _record_synthetic_file(repo, action) -> None:
    """Persist (or patch) a synthetic_files row after a FileAction plant.

    Idempotent on ``(decky_uuid, path)``: when the unique constraint
    fires (the file existed already), we patch the existing row's
    ``last_modified`` / ``content_hash`` / ``last_body`` / bump
    ``edit_count`` so the dashboard's "files this decky has grown"
    view stays accurate even when the orchestrator re-plants the same
    location.
    """
    body = action.content or ""
    content_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    row = {
        "decky_uuid": action.dst_uuid,
        "path": action.path,
        "persona": action.persona,
        "content_class": action.content_class,
        "created_at": now,
        "last_modified": now,
        "edit_count": 0,
        "content_hash": content_hash,
        "last_body": body,
    }
    try:
        await repo.record_synthetic_file(row)
    except Exception:  # noqa: BLE001
        existing = await repo.list_synthetic_files(
            decky_uuid=action.dst_uuid, limit=200,
        )
        match = next(
            (r for r in existing if r.get("path") == action.path), None,
        )
        if match is None:
            raise
        await repo.update_synthetic_file(
            match["uuid"],
            {
                "last_modified": now,
                "content_hash": content_hash,
                "last_body": body,
                "edit_count": int(match.get("edit_count", 0)) + 1,
            },
        )
