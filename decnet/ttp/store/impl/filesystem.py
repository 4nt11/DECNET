"""Filesystem-backed rule store — reads ``./rules/ttp/`` + inotify watch.

E.3.5 implementation. Linux-only by construction: the inotify dep
(``asyncinotify``) is non-portable, the platform guard in ``__init__``
refuses construction on macOS / Windows so the operator gets a
one-line readable error rather than a deep stack trace from the
inotify import.

Behavior summary (per ``development/TTP_TAGGING.md`` §"Worker shape" /
§"Tagging engines, layered" / §E.1.11 / §E.2.14b):

* :meth:`load_compiled` — walk ``self._rules_dir``, allowlist by
  basename, parse YAML, validate via :class:`RuleSchema`, compile each
  to a :class:`CompiledRule` carrying the cached :class:`RuleState`.
  Malformed YAML raises **at compile time**, never at evaluate time —
  the deploy-time vs runtime asymmetry pinned by E.2.5.
* :meth:`get_state` — returns the cached state (or default
  :class:`RuleState` for unknown rules); auto-reverts an expired
  state to default and emits a ``ttp.rule.state.{rule_id}`` event.
* :meth:`set_state` — writes to the in-process cache, restamps the
  cached :class:`CompiledRule` (so concurrent :meth:`load_compiled`
  reads see the new state), publishes a :class:`RuleChange` to every
  subscriber, and (if a bus is wired) publishes the matching
  ``ttp.rule.state.{rule_id}`` topic. Failures raise; operational
  state changes are not a tolerated-absence path.
* :meth:`subscribe_changes` — async iterator yielding one
  :class:`RuleChange` per per-rule edit; never batches.

The watcher loop is started lazily by :meth:`start` (or when entered
as an async context manager). Tests that only exercise state /
load_compiled don't need to start the watcher.

Atomic-swap concurrency property (E.2.14b): all compile work runs
under :attr:`_compile_lock`, so two filesystem events arriving
simultaneously are processed serially. The dispatch index values
(``CompiledRule`` NamedTuples) are frozen by virtue of being tuples;
swap is a single-statement dict assignment.
"""
from __future__ import annotations

import asyncio
import re
import sys
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Final, Type

import yaml

from decnet import telemetry as _telemetry
from decnet.bus import topics as _topics
from decnet.bus.publish import publish_safely
from decnet.logging import get_logger
from decnet.ttp.impl.rule_engine import CompiledRule, RuleSchema
from decnet.ttp.store.base import RuleChange, RuleState, RuleStore

if TYPE_CHECKING:
    from decnet.bus.base import BaseBus


_log = get_logger("ttp.store.filesystem")


@contextmanager
def _span(name: str, **attrs: Any) -> Iterator[Any]:
    """Span context manager gated on ``DECNET_DEVELOPER_TRACING``.

    When tracing is off, yields ``None`` after a single attribute
    lookup — matches the project's ``@traced`` / ``wrap_repository``
    pattern of zero per-call overhead in the disabled case. When on,
    opens an OTEL span via the (late-bound) tracer and applies
    *attrs* defensively.
    """
    if not _telemetry._ENABLED:
        yield None
        return
    # Late binding: tests monkeypatch ``decnet.telemetry.get_tracer``
    # at fixture setup; capturing the tracer at import time would
    # freeze the no-op tracer into the module forever.
    tracer = _telemetry.get_tracer("ttp.store")
    with tracer.start_as_current_span(name) as span:
        for key, value in attrs.items():
            try:
                span.set_attribute(key, value)
            except (TypeError, ValueError):
                continue
        yield span


# ── Filename allowlist ──────────────────────────────────────────────
# A path is accepted iff its basename FULLY matches this pattern. The
# allowlist (rather than a denylist) is deliberate per TTP_TAGGING.md
# §E.1.11: vim swap files (``.foo.yaml.swp``), atomic-save probes
# (``4913``), tilde backups (``foo.yaml~``), random tempfile
# conventions a future editor invents — all silently ignored, no
# parse, no log line. Denylists rot the moment an editor changes its
# scratch convention; the allowlist stops being clever.
_VALID_RULE_FILENAME: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9_]+\.ya?ml",
)


# ── Inotify event mask ──────────────────────────────────────────────
# Bit values from ``<sys/inotify.h>`` (man inotify(7)). Inlined as
# raw ints so this module is importable on non-Linux platforms (the
# ``__init__`` platform guard would otherwise be unreachable — the
# import-time guard would fire before the readable RuntimeError).
# E.2.14b cross-checks these against the asyncinotify library values.
_IN_CLOSE_WRITE: Final[int] = 0x00000008
_IN_MOVED_TO: Final[int] = 0x00000080
_IN_CREATE: Final[int] = 0x00000100
_IN_DELETE: Final[int] = 0x00000200

_INOTIFY_MASK: Final[int] = (
    _IN_CLOSE_WRITE | _IN_MOVED_TO | _IN_CREATE | _IN_DELETE
)


# ── Watch root ──────────────────────────────────────────────────────
# Resolved relative to the project root. Tests override via a tmp_path
# fixture to avoid touching the real ``./rules/`` during the suite.
_DEFAULT_RULES_DIR: Final[Path] = Path("./rules/ttp/")


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _is_expired(state: RuleState, now: datetime) -> bool:
    if state.expires_at is None:
        return False
    expires = state.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires < now


def _compile_one(parsed: RuleSchema, state: RuleState) -> CompiledRule:
    """Translate a validated :class:`RuleSchema` into a :class:`CompiledRule`.

    Each ``emits`` entry contributes a 4-tuple
    ``(technique_id, sub_technique_id, tactic, confidence)`` —
    consumed by :class:`RuleEngine` when fanning a single match into
    one tag per technique. Missing tactic / confidence in the YAML is
    a deploy-time error: a tag without a tactic can't render in the
    Navigator export, and a missing confidence has no sane default.
    The match spec is passed through verbatim — the engine owns
    interpretation of operator keys (``pattern``, ``contains``, …).
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
        description=parsed.description,
    )


def _parse_and_compile(path: Path, state: RuleState) -> CompiledRule:
    """Read one rule file off disk and produce a :class:`CompiledRule`.

    Raises :class:`yaml.YAMLError` on parse failure and
    :class:`pydantic.ValidationError` on schema failure — both are
    deploy-time signals; callers (``load_compiled`` / the inotify
    handler) decide whether to surface or skip.
    """
    raw = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(raw)
    if not isinstance(doc, dict):
        raise ValueError(
            f"rule file {path}: top-level YAML must be a mapping, "
            f"got {type(doc).__name__}",
        )
    parsed = RuleSchema.model_validate(doc)
    return _compile_one(parsed, state)


class FilesystemRuleStore(RuleStore):
    """``./rules/ttp/`` + inotify watch + in-process state cache.

    Right for single-host dev — state lost on restart is fine when the
    operator is local. Swarms use :class:`DatabaseRuleStore` so state
    survives restart and propagates across worker hosts.
    """

    def __init__(
        self,
        rules_dir: Path | None = None,
        *,
        bus: "BaseBus | None" = None,
    ) -> None:
        # Fail-fast platform guard. Per TTP_TAGGING.md §E.1.11: a
        # one-line operator-readable error beats a deep stack trace
        # from a downstream import.
        if sys.platform != "linux":
            raise RuntimeError(
                "FilesystemRuleStore requires Linux for inotify; use "
                "DatabaseRuleStore on this platform "
                "(DECNET_TTP_RULE_STORE_TYPE=database).",
            )
        self._rules_dir: Path = rules_dir or _DEFAULT_RULES_DIR
        self._bus = bus
        # In-process state cache — lost on restart by design.
        self._state: dict[str, RuleState] = {}
        # Compiled-rule mirror, keyed by rule_id. Single-statement
        # dict assignment is GIL-atomic to readers; concurrent
        # ``load_compiled`` snapshots therefore see either the old
        # CompiledRule or the new one, never a torn intermediate.
        self._compiled: dict[str, CompiledRule] = {}
        # ``rule_id`` → file path mirror for DELETE handling (the
        # inotify event carries the basename; we need the rule_id to
        # publish the per-rule reload topic).
        self._path_to_rule: dict[Path, str] = {}
        # Content-hash dedup so a single write that fires IN_CREATE
        # then IN_CLOSE_WRITE produces exactly one ``RuleChange``.
        # Editors are unfussy about multiplexing inotify events;
        # the per-rule fan-out contract demands one event per
        # observable change.
        self._content_hash: dict[str, int] = {}
        # Per-subscriber queues; ``subscribe_changes`` returns an
        # async iterator that owns one queue. Removing a queue on
        # generator close keeps the publisher list bounded.
        self._subscribers: list[asyncio.Queue[RuleChange]] = []
        # All compile work serializes on this lock so two filesystem
        # events arriving simultaneously process in order. The
        # E.2.14b "atomic-swap concurrency" property pins this.
        self._compile_lock = asyncio.Lock()
        self._watcher_task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()
        self._loaded = False

    # ── Lifecycle ───────────────────────────────────────────────────

    async def start(self) -> None:
        """Load the initial corpus and spawn the inotify watcher.

        Idempotent — calling twice is a no-op. Tests that don't need
        the watcher (e.g. pure ``set_state`` round-trips) can skip
        :meth:`start` entirely.
        """
        if self._watcher_task is not None:
            return
        self._rules_dir.mkdir(parents=True, exist_ok=True)
        await self.load_compiled()
        self._watcher_task = asyncio.create_task(
            self._watch_loop(), name="ttp.store.fs.watch",
        )

    async def stop(self) -> None:
        self._stop.set()
        task = self._watcher_task
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._watcher_task = None

    async def __aenter__(self) -> "FilesystemRuleStore":
        await self.start()
        return self

    async def __aexit__(
        self,
        _exc_type: Type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.stop()

    # ── ABC methods ─────────────────────────────────────────────────

    async def load_compiled(self) -> list[CompiledRule]:
        async with self._compile_lock:
            self._compiled.clear()
            self._path_to_rule.clear()
            if not self._rules_dir.exists():
                self._loaded = True
                return []
            for path in sorted(self._rules_dir.iterdir()):
                if not path.is_file():
                    continue
                if _VALID_RULE_FILENAME.fullmatch(path.name) is None:
                    continue
                state = self._state.get(path.stem, RuleState())
                # No expired-state revert on the bulk load path:
                # ``get_state`` is the documented entry point for
                # auto-revert (the conformance test consumes it).
                # Compiled-rule state mirrors what ``get_state``
                # would return synchronously.
                if _is_expired(state, _utcnow()):
                    state = RuleState()
                compiled = _parse_and_compile(path, state)
                self._compiled[compiled.rule_id] = compiled
                self._path_to_rule[path] = compiled.rule_id
            self._loaded = True
            return list(self._compiled.values())

    async def get_state(self, rule_id: str) -> RuleState:
        cached = self._state.get(rule_id)
        if cached is None:
            return RuleState()
        if _is_expired(cached, _utcnow()):
            # Auto-revert: drop the expired entry, restamp the
            # cached compiled rule, emit a state-change event so
            # dashboards reflect the revert.
            del self._state[rule_id]
            default = RuleState()
            self._restamp_compiled(rule_id, default)
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
        # Operational state changes are NOT a tolerated-absence path.
        # Failures here MUST raise rather than silently drop — the
        # E.2.14b conformance test pins this.
        with _span(
            "ttp.rule.state.change",
            rule_id=rule_id,
            state=state.state,
            set_by=set_by,
        ):
            stamped = replace(state, set_by=set_by, set_at=_utcnow())
            with _span("ttp.store.write_state"):
                self._state[rule_id] = stamped
                self._restamp_compiled(rule_id, stamped)
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
        # Register the queue eagerly (synchronously) so events emitted
        # *between* this call and the first ``__anext__`` are not
        # lost. An async generator with the queue inside its body
        # would defer registration until first iteration, racing
        # publishers — pinned by E.2.14b "incremental, never batched".
        queue: asyncio.Queue[RuleChange] = asyncio.Queue()
        self._subscribers.append(queue)
        return _ChangeIterator(queue, self._subscribers)

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

    def _restamp_compiled(self, rule_id: str, state: RuleState) -> None:
        existing = self._compiled.get(rule_id)
        if existing is None:
            return
        # NamedTuple._replace returns a fresh frozen tuple — single
        # dict assignment swaps it in atomically (GIL-atomic).
        self._compiled[rule_id] = existing._replace(state=state)

    async def _watch_loop(self) -> None:
        # Deferred import: the asyncinotify wheel is Linux-only and
        # gated by the ``__init__`` platform guard. Importing here
        # rather than at module top keeps the test suite importable
        # on macOS / Windows (where ``subscribe_changes`` is never
        # called and the import would otherwise fire on collection).
        from asyncinotify import Inotify, Mask  # noqa: PLC0415

        mask = (
            Mask.CLOSE_WRITE
            | Mask.MOVED_TO
            | Mask.CREATE
            | Mask.DELETE
        )
        try:
            with Inotify() as inotify:
                inotify.add_watch(self._rules_dir, mask)
                async for event in inotify:
                    if self._stop.is_set():
                        return
                    name = event.name
                    if name is None:
                        continue
                    basename = str(name)
                    # Filter is the FIRST thing the handler does. A
                    # filtered name produces NEITHER a parse attempt
                    # NOR a log line; observability noise on every
                    # vim save would be its own bug (E.2.14b).
                    if _VALID_RULE_FILENAME.fullmatch(basename) is None:
                        continue
                    path = self._rules_dir / basename
                    is_delete = bool(event.mask & Mask.DELETE)
                    try:
                        await self._handle_fs_event(path, is_delete=is_delete)
                    except Exception as exc:  # noqa: BLE001
                        # Per-event isolation: a malformed YAML
                        # landing on disk must not kill the watcher.
                        _log.warning(
                            "ttp.store.fs: rule reload failed path=%s: %s",
                            path,
                            exc,
                        )
        except asyncio.CancelledError:
            raise
        except Exception:
            _log.exception("ttp.store.fs: watcher loop crashed")
            raise

    async def _handle_fs_event(self, path: Path, *, is_delete: bool) -> None:
        async with self._compile_lock:
            if is_delete or not path.exists():
                rule_id = self._path_to_rule.pop(path, path.stem)
                if rule_id not in self._compiled:
                    return  # nothing was registered for this path
                self._compiled.pop(rule_id, None)
                self._content_hash.pop(rule_id, None)
                await self._emit_change(
                    RuleChange("definition", rule_id, _DELETED_SENTINEL),
                    bus_topic=_topics.ttp_rule_reloaded(rule_id),
                    payload={"rule_id": rule_id, "deleted": True},
                )
                return
            try:
                raw = path.read_text(encoding="utf-8")
            except FileNotFoundError:
                return
            if not raw.strip():
                # Empty placeholder (e.g. ``touch new.yaml`` followed
                # by content later). Skip — the CLOSE_WRITE that lands
                # the real content will compile.
                return
            content_hash = hash(raw)
            state = self._state.get(path.stem, RuleState())
            if _is_expired(state, _utcnow()):
                state = RuleState()
            compiled = _parse_and_compile(path, state)
            if self._content_hash.get(compiled.rule_id) == content_hash:
                # Duplicate event for the same on-disk bytes (e.g.
                # IN_CREATE then IN_CLOSE_WRITE on a single write).
                # The first event already emitted the change.
                return
            self._content_hash[compiled.rule_id] = content_hash
            self._compiled[compiled.rule_id] = compiled
            self._path_to_rule[path] = compiled.rule_id
            await self._emit_change(
                RuleChange("definition", compiled.rule_id, compiled),
                bus_topic=_topics.ttp_rule_reloaded(compiled.rule_id),
                payload={
                    "rule_id": compiled.rule_id,
                    "rule_version": compiled.rule_version,
                },
            )


class _ChangeIterator:
    """Async iterator over a per-subscriber :class:`asyncio.Queue`.

    Owns its queue lifetime: the queue is registered on construction
    (so events fired before the first ``__anext__`` are buffered) and
    deregistered on ``aclose()``.
    """

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


# Sentinel value carried in :class:`RuleChange.new_value` when a rule
# was deleted. ``CompiledRule`` is the documented type, so we ship a
# minimal placeholder instance with empty ``emits`` — engines treat
# empty-emits CompiledRules as "drop from dispatch index". Pinned as
# a module-level singleton so equality check in tests is identity.
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


__all__ = [
    "FilesystemRuleStore",
    "_INOTIFY_MASK",
    "_VALID_RULE_FILENAME",
]
