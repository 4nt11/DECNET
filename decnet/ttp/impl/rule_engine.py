"""Rule engine contract — `CompiledRule`, `RuleEngine`, `RuleSchema`.

Contract step E.1.5 of ``development/TTP_TAGGING.md``. Shape only — no
real evaluation logic, no YAML parsing, no dispatch. The implementation
phase (E.3) replaces every empty body in this file; *callers compile
against the public surface here today* so subsequent contract commits
(lifters E.1.6, worker E.1.7) can import without churn.

Three classes live in this module:

* :class:`CompiledRule` — frozen, hashable record the engine evaluates
  against. The store produces these after validating raw YAML through
  :class:`RuleSchema` and stamping operational :class:`RuleState`.
* :class:`RuleSchema` — Pydantic model for raw YAML rule shape.
  Operationally owned by the store (it reads disk and validates),
  declared here per the file mapping in the design doc — keeping the
  schema and the compiled record next to each other lets reviewers see
  the YAML→runtime translation in one diff.
* :class:`RuleEngine` — consumes a :class:`RuleStore`, evaluates one
  :class:`TaggerEvent` at a time. Hot-reload via
  :meth:`RuleEngine.watch_store` swaps individual compiled rules in the
  dispatch index atomically — never bulk-rebuilds.

The :class:`RuleStore` and :class:`RuleState` types arrive in E.1.11;
they are forward-referenced under :data:`TYPE_CHECKING` here so this
file is importable before that step lands.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, NamedTuple

from pydantic import BaseModel, Field

from decnet import telemetry as _telemetry
from decnet.logging import get_logger
from decnet.ttp.base import Tagger, TaggerEvent
from decnet.ttp.impl._rule_index import RuleIndex
from decnet.ttp.impl._state import apply_ceiling, is_active
from decnet.web.db.models.ttp import TTPTag, compute_tag_uuid

if TYPE_CHECKING:
    # Store contracts ship in E.1.11. Forward-referenced under
    # TYPE_CHECKING so this module is importable in the contract phase
    # without creating a circular shape dependency on a not-yet-shipped
    # subpackage. Concrete construction happens at the worker layer
    # (E.1.7) where both halves are in scope.
    from decnet.ttp.store.base import RuleChange, RuleState, RuleStore


_log = get_logger("ttp.engine")


@contextmanager
def _span(name: str, **attrs: Any) -> Iterator[Any]:
    """Span context manager gated on ``DECNET_DEVELOPER_TRACING``.

    Same shape as the helpers in :mod:`decnet.ttp.store.impl.filesystem`
    / :mod:`decnet.ttp.store.impl.database`: zero per-call overhead when
    tracing is off (single attribute lookup, then yield ``None``);
    late-bound tracer when on so the test_tracing monkeypatch reaches
    us. Modeled on the project's ``@traced`` / ``wrap_repository``
    no-overhead-when-disabled pattern.
    """
    if not _telemetry._ENABLED:
        yield None
        return
    tracer = _telemetry.get_tracer("ttp.engine")
    with tracer.start_as_current_span(name) as span:
        for key, value in attrs.items():
            try:
                span.set_attribute(key, value)
            except (TypeError, ValueError):
                continue
        yield span


# ATT&CK release stamped on every emitted tag. Pinned at the engine
# layer rather than per-rule because rule authors don't manage ATT&CK
# matrix drift; the engine owns that. Bumping this value invalidates
# tag UUID continuity across deploys, so the bump must land alongside a
# documented ATT&CK upgrade per TTP_TAGGING.md §"Hard parts §8".
_ATTACK_RELEASE: str = "v15.1"


class CompiledRule(NamedTuple):
    """Runtime-ready representation of one YAML rule.

    Frozen by virtue of being a NamedTuple — the design doc's
    "atomic-swap concurrency" property (E.2.14b) requires that a rule
    in the dispatch index can never be torn mid-evaluate. NamedTuple
    rather than ``@dataclass(frozen=True)`` because instances are
    swapped *by replacement* and benefit from the cheaper allocator;
    `FrozenInstanceError` parity is preserved by the in-test smoke
    signal in E.2.14b.

    Fields mirror the YAML rule shape one-to-one except for ``state``,
    which the store stamps in at compile time after merging operational
    state (enabled / disabled / clipped, confidence ceiling, expiry).
    The engine therefore never reads :class:`RuleState` directly — it
    only consults the value attached to each :class:`CompiledRule`.
    """

    rule_id: str
    rule_version: int
    name: str
    #: ``source_kind`` strings the rule is allowed to fire on. Frozen so
    #: it can live in a set / dispatch index key without copying.
    applies_to: frozenset[str]
    #: Opaque match spec — interpretation belongs to the engine impl
    #: phase (E.3). Kept ``dict[str, Any]`` here rather than typed so
    #: rule authors can extend match operators without touching the ABC.
    match_spec: dict[str, Any]
    #: ``((technique_id, sub_technique_id | None, tactic, confidence), ...)``
    #: per emit. Tuple-of-tuples, not list, so the record stays hashable.
    #: One YAML rule may emit N tags from a single match — see
    #: TTP_TAGGING.md §"One event maps to many techniques".
    emits: tuple[tuple[str, str | None, str, float], ...]
    #: Names of evidence keys the rule populates on emitted tags.
    evidence_fields: tuple[str, ...]
    #: Operational state stamped in by the store at compile time.
    state: "RuleState"


class RuleSchema(BaseModel):
    """Pydantic model for the raw YAML rule shape.

    Validation surface only — no runtime semantics. The store calls
    :meth:`model_validate` on each parsed YAML document; the engine
    never touches this class. Adding a new top-level rule field means
    adding it here AND extending :class:`CompiledRule` in the same
    commit, so the YAML→runtime mapping stays one-to-one.
    """

    rule_id: str
    rule_version: int
    name: str
    applies_to: list[str]
    match: dict[str, Any]
    #: ``[{"tactic": "TA0007", "technique_id": "T1083",
    #:    "sub_technique_id": "T1083.001"?, "confidence": 0.85}, ...]``
    #: Per-emit tactic + confidence ride here so a single rule can carry
    #: multiple precision targets (the "one event maps to many techniques"
    #: case from TTP_TAGGING.md, including different confidences per
    #: technique on the same match).
    emits: list[dict[str, Any]]
    evidence_fields: list[str] = Field(default_factory=list)


class RuleEngine:
    """Evaluates :class:`TaggerEvent` against compiled rules from a store.

    Construction takes the store reference; the engine never reads YAML
    directly. The dispatch index (``self._by_kind``) is rebuilt by
    :meth:`watch_store` on each per-rule change event from
    ``store.subscribe_changes()`` — never bulk-rebuilt — so an edit to
    one rule cannot stall evaluation of unrelated rules.

    Contract phase: every method has an empty body. The implementation
    phase (E.3) wires real compile + evaluate logic; callers compiling
    against the public surface today will not need to change.
    """

    def __init__(self, store: "RuleStore") -> None:
        self._store = store
        # Dispatch index extracted to RuleIndex so per-source lifters
        # (E.3.9–E.3.13) reuse the same atomic-swap protocol. Legacy
        # ``_by_kind`` / ``_by_rule`` properties below proxy to it for
        # callers (and tests) that still poke the dispatch index directly.
        self._index = RuleIndex()

    @property
    def _by_kind(self) -> dict[str, list[CompiledRule]]:
        return self._index._by_kind

    @_by_kind.setter
    def _by_kind(self, value: dict[str, list[CompiledRule]]) -> None:
        self._index._by_kind = value

    @property
    def _by_rule(self) -> dict[str, CompiledRule]:
        return self._index._by_rule

    @_by_rule.setter
    def _by_rule(self, value: dict[str, CompiledRule]) -> None:
        self._index._by_rule = value

    async def evaluate(self, event: TaggerEvent) -> list[TTPTag]:
        """Return zero or more tags produced by rules matching *event*.

        Dispatches by ``event.source_kind``; for each rule whose
        ``applies_to`` set covers the kind, runs the match spec against
        ``event.payload`` and emits one :class:`TTPTag` per ``emits``
        entry. Confidence is the per-emit base scaled by the rule's
        :class:`RuleState.confidence_max` ceiling (no-op when ``None``).
        Disabled rules are skipped; the store auto-reverts expired
        states, but the engine double-checks ``expires_at`` as
        defense-in-depth.
        """
        rules = self._index.by_kind(event.source_kind)
        if not rules:
            return []
        with _span(
            "ttp.eval",
            attacker_uuid=str(event.attacker_uuid or ""),
            identity_uuid=str(event.identity_uuid or ""),
            source_kind=event.source_kind,
        ):
            return _evaluate_rules(rules, event)

    async def watch_store(self) -> None:
        """Subscribe to per-rule changes and atomically swap them in.

        Delegates to :meth:`RuleIndex.watch`: loads the initial corpus
        from :meth:`RuleStore.load_compiled`, builds the dispatch
        index, then drains :meth:`RuleStore.subscribe_changes` forever.
        Each ``definition`` change replaces the affected rule wholesale;
        each ``state`` change re-stamps the existing
        :class:`CompiledRule`'s ``state`` field via NamedTuple
        ``_replace`` (single dict assignment, no in-place mutation).
        """
        await self._index.watch(self._store)

    # ── Internals ───────────────────────────────────────────────────
    # Back-compat shims — the dispatch-index protocol moved into
    # :class:`RuleIndex`. Existing callers / tests that poke at
    # ``_install`` / ``_evict`` / ``_apply_change`` keep working.

    def _install(self, rule: CompiledRule) -> None:
        self._index.install(rule)

    def _evict(self, rule_id: str) -> None:
        self._index.evict(rule_id)

    def _apply_change(
        self, change: "RuleChange", state_cls: type,
    ) -> None:
        self._index.apply_change(change, state_cls)


def _match_event(rule: CompiledRule, event: TaggerEvent) -> bool:
    """Run the rule's match spec against ``event.payload``.

    For v0 the only operator is ``pattern`` — a regex against a
    payload field. The field name comes from ``match_spec["field"]``
    if present, otherwise the per-source-kind default
    (``command_text`` for ``command``, ``raw_url`` for
    ``http_request``, etc.). A future PR can extend this to
    ``contains``, ``equals``, ``in_set`` without touching the engine
    surface — only this function changes.
    """
    spec = rule.match_spec
    pattern = spec.get("pattern")
    if pattern is None:
        return False
    field = spec.get("field") or _default_field(event.source_kind)
    if field is None:
        return False
    haystack = event.payload.get(field)
    if not isinstance(haystack, str):
        return False
    try:
        return re.search(pattern, haystack) is not None
    except re.error:
        # Malformed regex made it past schema validation — log and
        # don't fire. The deploy-time hook (load_compiled) catches
        # most of these; this path is the runtime fallback.
        _log.warning(
            "ttp.engine: bad regex in rule %s: %r", rule.rule_id, pattern,
        )
        return False


def _default_field(source_kind: str) -> str | None:
    return _DEFAULT_MATCH_FIELD.get(source_kind)


# Per-source_kind default field for the ``pattern`` operator. New
# source_kinds can override via ``match.field`` in the YAML rule.
_DEFAULT_MATCH_FIELD: dict[str, str] = {
    "command": "command_text",
    "http_request": "raw_url",
    "email": "subject",
    "intel": "verdict",
    "canary_fingerprint": "ua_signature",
    "auth_attempt": "username",
    "payload": "payload_text",
}


def _evaluate_rules(
    rules: list[CompiledRule], event: TaggerEvent,
) -> list[TTPTag]:
    out: list[TTPTag] = []
    for rule in rules:
        if not is_active(rule.state):
            continue
        if not _match_event(rule, event):
            continue
        with _span(
            "ttp.rule.fire",
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
        ) as span:
            for technique_id, sub_technique_id, tactic, base_conf in rule.emits:
                if span is not None:
                    try:
                        span.set_attribute("technique_id", technique_id)
                    except (TypeError, ValueError):
                        pass
                confidence = apply_ceiling(base_conf, rule.state)
                tag_uuid = compute_tag_uuid(
                    source_kind=event.source_kind,
                    source_id=event.source_id,
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    technique_id=technique_id,
                    sub_technique_id=sub_technique_id,
                )
                evidence: dict[str, Any] = {
                    field: event.payload.get(field)
                    for field in rule.evidence_fields
                    if field in event.payload
                }
                out.append(TTPTag(
                    uuid=tag_uuid,
                    source_kind=event.source_kind,
                    source_id=event.source_id,
                    attacker_uuid=event.attacker_uuid,
                    identity_uuid=event.identity_uuid,
                    session_id=event.session_id,
                    decky_id=event.decky_id,
                    tactic=tactic,
                    technique_id=technique_id,
                    sub_technique_id=sub_technique_id,
                    confidence=confidence,
                    rule_id=rule.rule_id,
                    rule_version=rule.rule_version,
                    evidence=evidence,
                    attack_release=_ATTACK_RELEASE,
                ))
    return out


def _is_engine_owned(rule: CompiledRule) -> bool:
    """Predicate: rule belongs to the generic RuleEngine, not a lifter.

    Per-source lifters (Behavioral, Intel, …) tag their rules with
    ``match.kind: lifter:<name>_*``. The :class:`RuleEngineTagger`
    claims everything else — pure ``pattern`` rules whose semantics
    are "regex against a payload field" with no cross-event state.
    """
    kind = rule.match_spec.get("kind", "")
    if isinstance(kind, str) and kind.startswith("lifter:"):
        return False
    return True


class RuleEngineTagger(Tagger):
    """Tagger adapter that wires :class:`RuleEngine` into the composite.

    The composite tagger fans events out to its children by
    ``HANDLES``; without this adapter the canonical rule-based engine
    from §"Tagging engines, layered §1" of TTP_TAGGING.md never sees
    any traffic. This class is intentionally thin — all dispatch and
    hot-reload logic lives in :class:`RuleEngine` / :class:`RuleIndex`;
    we only translate between the ``Tagger.tag`` ABC and
    :meth:`RuleEngine.evaluate`, and route ``watch_store()`` through a
    predicate that excludes lifter-owned rules so the engine's
    dispatch index doesn't hold rules another tagger already claims.

    ``HANDLES`` enumerates the source kinds whose YAML rules typically
    live outside any per-source lifter — shell command rules
    (``command``), HTTP request pattern rules (``http_request``),
    auth attempts handled by raw regex rather than the
    :class:`CredentialLifter` cross-event counter, and generic
    ``payload`` matches. The composite uses this for routing; the
    engine itself filters by ``applies_to`` from the YAML.
    """

    name = "rule_engine"
    HANDLES = frozenset({"command", "http_request", "auth_attempt", "payload"})

    def __init__(self, store: "RuleStore") -> None:
        self._engine = RuleEngine(store)
        self._store = store

    async def tag(self, event: TaggerEvent) -> list[TTPTag]:
        return await self._engine.evaluate(event)

    async def watch_store(self) -> None:
        # Filter to engine-owned rules so the dispatch index stays
        # disjoint from per-lifter ownership. Without the predicate
        # the engine would carry every lifter's rules too — they would
        # never match (no `pattern` operator), but they would inflate
        # the index and confuse tooling.
        await self._engine._index.watch(
            self._store, predicate=_is_engine_owned,
        )


__all__ = [
    "CompiledRule",
    "RuleEngine",
    "RuleEngineTagger",
    "RuleSchema",
]
