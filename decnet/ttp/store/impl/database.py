"""Database-backed rule store — ``ttp_rule`` + ``ttp_rule_state``.

E.3.6 implementation. Right for swarm: master syncs filesystem changes
into ``ttp_rule``, workers tail the DB, state in ``ttp_rule_state``
survives restart and propagates to every worker. Pick via
``DECNET_TTP_RULE_STORE_TYPE=database``.

No platform guard — works on macOS / Windows where the filesystem
backend's inotify dependency is unavailable.

Mechanics:

* :meth:`load_compiled` — read every row of ``ttp_rule``, parse the
  stored ``yaml_content`` through :class:`RuleSchema`, stamp the
  matching :class:`RuleState` from ``ttp_rule_state`` (or default
  ``RuleState`` if no row exists). Malformed YAML in ``yaml_content``
  raises immediately — same deploy-time-not-runtime asymmetry as the
  filesystem backend.
* :meth:`get_state` — single-row lookup against ``ttp_rule_state``
  with the same ``expires_at`` auto-revert + bus-event semantics as
  the filesystem store.
* :meth:`set_state` — upsert into ``ttp_rule_state``; failures raise
  rather than silently drop. Publishes the change through the
  in-process subscriber fan-out and (if a bus is wired) the matching
  ``ttp.rule.state.{rule_id}`` topic.
* :meth:`subscribe_changes` — async iterator backed by a per-subscriber
  queue. Direct :meth:`set_state` calls feed the queue synchronously;
  cross-process changes (master writes a new ``ttp_rule`` row, this
  worker tails it) are picked up by :meth:`tail_db` — a poll loop the
  worker bootstrap (E.3.14) wires onto the asyncio event loop.

The master-side filesystem→DB sync helper is
:meth:`sync_from_filesystem`, which subscribes to a
:class:`FilesystemRuleStore` and projects its
:class:`RuleChange` events onto upserts/deletes against ``ttp_rule``.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Final

import yaml
from sqlalchemy import delete as sa_delete
from sqlalchemy import select as sa_select
from sqlmodel import col

from decnet import telemetry as _telemetry
from decnet.bus import topics as _topics
from decnet.bus.publish import publish_safely
from decnet.logging import get_logger
from decnet.ttp.impl.rule_engine import CompiledRule, RuleSchema
from decnet.ttp.store.base import RuleChange, RuleState, RuleStore
from decnet.web.db.models import TTPRule, TTPRuleState

if TYPE_CHECKING:
    from decnet.bus.base import BaseBus
    from decnet.ttp.store.impl.filesystem import FilesystemRuleStore
    from decnet.web.db.repository import BaseRepository


_log = get_logger("ttp.store.database")


@contextmanager
def _span(name: str, **attrs: Any) -> Iterator[Any]:
    """Span context manager gated on ``DECNET_DEVELOPER_TRACING``.

    Mirrors the helper in :mod:`decnet.ttp.store.impl.filesystem`: zero
    per-call overhead when tracing is off, late-bound tracer when on
    (so ``test_tracing.py``'s monkeypatch of
    :func:`decnet.telemetry.get_tracer` reaches us).
    """
    if not _telemetry._ENABLED:
        yield None
        return
    tracer = _telemetry.get_tracer("ttp.store")
    with tracer.start_as_current_span(name) as span:
        for key, value in attrs.items():
            try:
                span.set_attribute(key, value)
            except (TypeError, ValueError):
                continue
        yield span


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _is_expired(state: RuleState, now: datetime) -> bool:
    if state.expires_at is None:
        return False
    expires = state.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires < now


def _row_to_state(row: TTPRuleState) -> RuleState:
    state_value = row.state
    if state_value not in ("enabled", "disabled", "clipped"):
        # Pinned at the contract layer so an out-of-band SQL UPDATE
        # cannot smuggle a bogus state through.
        raise ValueError(
            f"ttp_rule_state.state for {row.rule_id!r} is "
            f"{state_value!r}; must be one of enabled/disabled/clipped",
        )
    return RuleState(
        state=state_value,  # type: ignore[arg-type]
        confidence_max=row.confidence_max,
        expires_at=row.expires_at,
        reason=row.reason,
        set_by=row.set_by,
        set_at=row.set_at,
    )


def _compile_one(parsed: RuleSchema, state: RuleState) -> CompiledRule:
    """Mirror of :func:`decnet.ttp.store.impl.filesystem._compile_one`.

    Same 4-tuple emits shape so a rule round-trips identically through
    either backend. Kept as a sibling rather than imported from the FS
    module to avoid dragging the asyncinotify import onto non-Linux
    hosts that only use the database backend.
    """
    emits: list[tuple[str, str | None, str, float]] = []
    for entry in parsed.emits:
        tid = entry.get("technique_id")
        if not tid:
            raise ValueError(
                f"rule {parsed.rule_id}: every emits entry needs technique_id",
            )
        sub_raw = entry.get("sub_technique_id")
        sub = sub_raw if sub_raw else None
        tactic = entry.get("tactic")
        if not tactic:
            raise ValueError(
                f"rule {parsed.rule_id}: emit for {tid} needs a tactic",
            )
        confidence_raw = entry.get("confidence")
        if confidence_raw is None:
            raise ValueError(
                f"rule {parsed.rule_id}: emit for {tid} needs a confidence",
            )
        confidence = float(confidence_raw)
        emits.append((str(tid), sub, str(tactic), confidence))
    return CompiledRule(
        rule_id=parsed.rule_id,
        rule_version=parsed.rule_version,
        name=parsed.name,
        applies_to=frozenset(parsed.applies_to),
        match_spec=dict(parsed.match),
        emits=tuple(emits),
        evidence_fields=tuple(parsed.evidence_fields),
        state=state,
    )


def _yaml_to_compiled(yaml_text: str, state: RuleState) -> CompiledRule:
    doc = yaml.safe_load(yaml_text)
    if not isinstance(doc, dict):
        raise ValueError(
            "ttp_rule.yaml_content top-level YAML must be a mapping",
        )
    parsed = RuleSchema.model_validate(doc)
    return _compile_one(parsed, state)


def _compiled_to_yaml(compiled: CompiledRule) -> str:
    """Serialize a :class:`CompiledRule` back to a YAML rule body for
    master-side filesystem→DB sync. Mirrors :class:`RuleSchema`."""
    emits: list[dict[str, Any]] = []
    for technique_id, sub, tactic, confidence in compiled.emits:
        entry: dict[str, Any] = {
            "technique_id": technique_id,
            "tactic": tactic,
            "confidence": confidence,
        }
        if sub:
            entry["sub_technique_id"] = sub
        emits.append(entry)
    return yaml.safe_dump({
        "rule_id": compiled.rule_id,
        "rule_version": compiled.rule_version,
        "name": compiled.name,
        "applies_to": sorted(compiled.applies_to),
        "match": compiled.match_spec,
        "emits": emits,
        "evidence_fields": list(compiled.evidence_fields),
    }, sort_keys=False)


class _ChangeIterator:
    def __init__(
        self,
        queue: asyncio.Queue[RuleChange],
        subscribers: list[asyncio.Queue[RuleChange]],
    ) -> None:
        self._queue = queue
        self._subscribers = subscribers

    def __aiter__(self) -> "_ChangeIterator":
        return self

    async def __anext__(self) -> RuleChange:
        return await self._queue.get()

    async def aclose(self) -> None:
        try:
            self._subscribers.remove(self._queue)
        except ValueError:
            pass


class DatabaseRuleStore(RuleStore):
    """``ttp_rule`` content + ``ttp_rule_state`` operational state."""

    def __init__(
        self,
        repo: "BaseRepository | None" = None,
        *,
        bus: "BaseBus | None" = None,
    ) -> None:
        self._repo = repo
        self._bus = bus
        self._subscribers: list[asyncio.Queue[RuleChange]] = []
        self._tail_task: asyncio.Task[None] | None = None
        self._tail_watermark: datetime | None = None
        self._sync_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._lazy_lock = asyncio.Lock()

    async def _ensure_repo(self) -> "BaseRepository":
        if self._repo is not None:
            return self._repo
        # Lazy in-memory SQLite repo so unit tests that just call
        # ``DatabaseRuleStore()`` get a usable backend without ceremony.
        # Production callers always pass an explicit repo via the
        # worker bootstrap (E.3.14).
        async with self._lazy_lock:
            if self._repo is not None:
                return self._repo
            from decnet.web.db.sqlite.repository import SQLiteRepository  # noqa: PLC0415

            repo = SQLiteRepository(db_path=":memory:")
            await repo.initialize()
            self._repo = repo
        return self._repo

    # ── ABC methods ─────────────────────────────────────────────────

    async def load_compiled(self) -> list[CompiledRule]:
        repo = await self._ensure_repo()
        async with repo._session() as session:  # type: ignore[attr-defined]
            rule_rows = (
                await session.execute(sa_select(TTPRule))
            ).scalars().all()
            state_rows = (
                await session.execute(sa_select(TTPRuleState))
            ).scalars().all()
        states: dict[str, RuleState] = {}
        now = _utcnow()
        for row in state_rows:
            cached = _row_to_state(row)
            if _is_expired(cached, now):
                cached = RuleState()
            states[row.rule_id] = cached
        compiled: list[CompiledRule] = []
        for rule_row in rule_rows:
            state = states.get(rule_row.rule_id, RuleState())
            compiled.append(_yaml_to_compiled(rule_row.yaml_content, state))
        return compiled

    async def get_state(self, rule_id: str) -> RuleState:
        repo = await self._ensure_repo()
        async with repo._session() as session:  # type: ignore[attr-defined]
            row = (
                await session.execute(
                    sa_select(TTPRuleState).where(
                        col(TTPRuleState.rule_id) == rule_id,
                    ),
                )
            ).scalars().first()
        if row is None:
            return RuleState()
        cached = _row_to_state(row)
        if _is_expired(cached, _utcnow()):
            # Auto-revert: drop the row, emit the change event.
            await self._delete_state_row(rule_id)
            default = RuleState()
            await self._emit_change(
                RuleChange("state", rule_id, default),
                bus_topic=_topics.ttp_rule_state(rule_id),
                payload={"rule_id": rule_id, "auto_revert": True},
            )
            return default
        return cached

    async def set_state(
        self,
        rule_id: str,
        state: RuleState,
        set_by: str,
    ) -> None:
        with _span(
            "ttp.rule.state.change",
            rule_id=rule_id,
            state=state.state,
            set_by=set_by,
        ):
            stamped = replace(state, set_by=set_by, set_at=_utcnow())
            with _span("ttp.store.write_state"):
                await self._upsert_state_row(rule_id, stamped)
            with _span("ttp.rule.publish"):
                await self._emit_change(
                    RuleChange("state", rule_id, stamped),
                    bus_topic=_topics.ttp_rule_state(rule_id),
                    payload={
                        "rule_id": rule_id,
                        "state": stamped.state,
                        "set_by": set_by,
                    },
                )

    def subscribe_changes(self) -> AsyncIterator[RuleChange]:
        queue: asyncio.Queue[RuleChange] = asyncio.Queue()
        self._subscribers.append(queue)
        return _ChangeIterator(queue, self._subscribers)

    # ── Internals: subscriber fan-out ───────────────────────────────

    async def _emit_change(
        self,
        change: RuleChange,
        *,
        bus_topic: str,
        payload: dict[str, Any],
    ) -> None:
        for queue in list(self._subscribers):
            await queue.put(change)
        if self._bus is not None:
            await publish_safely(self._bus, bus_topic, payload)

    # ── Internals: ttp_rule_state writes ────────────────────────────

    async def _upsert_state_row(
        self, rule_id: str, state: RuleState,
    ) -> None:
        repo = await self._ensure_repo()
        async with repo._session() as session:  # type: ignore[attr-defined]
            existing = (
                await session.execute(
                    sa_select(TTPRuleState).where(
                        col(TTPRuleState.rule_id) == rule_id,
                    ),
                )
            ).scalars().first()
            if existing is None:
                session.add(
                    TTPRuleState(
                        rule_id=rule_id,
                        state=state.state,
                        confidence_max=state.confidence_max,
                        expires_at=state.expires_at,
                        reason=state.reason,
                        set_by=state.set_by,
                        set_at=state.set_at or _utcnow(),
                    ),
                )
            else:
                existing.state = state.state
                existing.confidence_max = state.confidence_max
                existing.expires_at = state.expires_at
                existing.reason = state.reason
                existing.set_by = state.set_by
                existing.set_at = state.set_at or _utcnow()
                session.add(existing)
            await session.commit()

    async def _delete_state_row(self, rule_id: str) -> None:
        repo = await self._ensure_repo()
        async with repo._session() as session:  # type: ignore[attr-defined]
            await session.execute(
                sa_delete(TTPRuleState).where(
                    col(TTPRuleState.rule_id) == rule_id,
                ),
            )
            await session.commit()

    # ── ttp_rule writes (master-side filesystem sync) ───────────────

    async def upsert_rule(
        self,
        compiled: CompiledRule,
        *,
        source_path: str,
        updated_by: str,
    ) -> None:
        """Master-side: write a rule definition into ``ttp_rule``.

        Workers tailing the DB pick up the change via :meth:`tail_db`
        and emit ``RuleChange("definition", ...)`` events to local
        engines. Used by :meth:`sync_from_filesystem`.
        """
        repo = await self._ensure_repo()
        yaml_text = _compiled_to_yaml(compiled)
        async with repo._session() as session:  # type: ignore[attr-defined]
            existing = (
                await session.execute(
                    sa_select(TTPRule).where(
                        col(TTPRule.rule_id) == compiled.rule_id,
                    ),
                )
            ).scalars().first()
            now = _utcnow()
            if existing is None:
                session.add(TTPRule(
                    rule_id=compiled.rule_id,
                    rule_version=compiled.rule_version,
                    source_path=source_path,
                    yaml_content=yaml_text,
                    updated_at=now,
                    updated_by=updated_by,
                ))
            else:
                existing.rule_version = compiled.rule_version
                existing.source_path = source_path
                existing.yaml_content = yaml_text
                existing.updated_at = now
                existing.updated_by = updated_by
                session.add(existing)
            await session.commit()
        await self._emit_change(
            RuleChange("definition", compiled.rule_id, compiled),
            bus_topic=_topics.ttp_rule_reloaded(compiled.rule_id),
            payload={
                "rule_id": compiled.rule_id,
                "rule_version": compiled.rule_version,
            },
        )

    async def delete_rule(self, rule_id: str) -> None:
        repo = await self._ensure_repo()
        async with repo._session() as session:  # type: ignore[attr-defined]
            await session.execute(
                sa_delete(TTPRule).where(col(TTPRule.rule_id) == rule_id),
            )
            await session.commit()
        await self._emit_change(
            RuleChange("definition", rule_id, _DELETED_SENTINEL),
            bus_topic=_topics.ttp_rule_reloaded(rule_id),
            payload={"rule_id": rule_id, "deleted": True},
        )

    # ── Master: filesystem→DB sync ──────────────────────────────────

    async def sync_from_filesystem(
        self,
        fs_store: "FilesystemRuleStore",
        *,
        updated_by: str = "filesystem",
    ) -> None:
        """Subscribe to a :class:`FilesystemRuleStore` and project its
        ``RuleChange`` events onto ``ttp_rule`` upserts/deletes.

        Runs forever; the caller (the master worker bootstrap E.3.14)
        cancels it during shutdown. Definition deletes (the FS store
        emits a sentinel ``CompiledRule`` with empty emits) project
        onto a ``ttp_rule`` row delete.
        """
        async for change in fs_store.subscribe_changes():
            try:
                if change.change_kind != "definition":
                    continue
                value = change.new_value
                if not isinstance(value, CompiledRule):
                    continue
                if not value.emits and not value.applies_to:
                    await self.delete_rule(change.rule_id)
                else:
                    await self.upsert_rule(
                        value,
                        source_path=f"./rules/ttp/{change.rule_id}.yaml",
                        updated_by=updated_by,
                    )
            except Exception:  # noqa: BLE001
                _log.exception(
                    "ttp.store.db: master sync failed rule_id=%s",
                    change.rule_id,
                )

    # ── Worker: DB-tail polling ─────────────────────────────────────

    async def tail_db(self, *, poll_interval: float = 1.0) -> None:
        """Poll ``ttp_rule.updated_at`` past a watermark; emit
        :class:`RuleChange` events for each row that moved.

        Used by worker bootstrap (E.3.14) so a swarm of workers each
        receive per-rule definition changes without a shared bus
        round-trip. The watermark advances on every observed row;
        first poll initializes it to "now" so we don't replay history.
        """
        repo = await self._ensure_repo()
        if self._tail_watermark is None:
            self._tail_watermark = _utcnow()
        while not self._stop.is_set():
            try:
                async with repo._session() as session:  # type: ignore[attr-defined]
                    rows = (
                        await session.execute(
                            sa_select(TTPRule).where(
                                col(TTPRule.updated_at) > self._tail_watermark,
                            ),
                        )
                    ).scalars().all()
                for rule_row in rows:
                    state = await self.get_state(rule_row.rule_id)
                    compiled = _yaml_to_compiled(rule_row.yaml_content, state)
                    await self._emit_change(
                        RuleChange("definition", compiled.rule_id, compiled),
                        bus_topic=_topics.ttp_rule_reloaded(compiled.rule_id),
                        payload={
                            "rule_id": compiled.rule_id,
                            "rule_version": compiled.rule_version,
                        },
                    )
                    if (
                        self._tail_watermark is None
                        or rule_row.updated_at > self._tail_watermark
                    ):
                        self._tail_watermark = rule_row.updated_at
            except Exception:  # noqa: BLE001
                _log.exception("ttp.store.db: tail poll failed")
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=poll_interval,
                )
            except asyncio.TimeoutError:
                continue

    async def stop(self) -> None:
        self._stop.set()
        for task in (self._tail_task, self._sync_task):
            if task is not None:
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001
                    pass
        self._tail_task = None
        self._sync_task = None


_DELETED_SENTINEL: Final[CompiledRule] = CompiledRule(
    rule_id="",
    rule_version=0,
    name="",
    applies_to=frozenset(),
    match_spec={},
    emits=(),
    evidence_fields=(),
    state=RuleState(),
)


__all__ = ["DatabaseRuleStore"]
