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

from typing import TYPE_CHECKING, Any, NamedTuple

from pydantic import BaseModel, Field

from decnet.ttp.base import TaggerEvent
from decnet.web.db.models.ttp import TTPTag

if TYPE_CHECKING:
    # Store contracts ship in E.1.11. Forward-referenced under
    # TYPE_CHECKING so this module is importable in the contract phase
    # without creating a circular shape dependency on a not-yet-shipped
    # subpackage. Concrete construction happens at the worker layer
    # (E.1.7) where both halves are in scope.
    from decnet.ttp.store.base import RuleState, RuleStore


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
    #: ``((technique_id, sub_technique_id | None), ...)``. Tuple, not
    #: list, so the record stays hashable.
    emits: tuple[tuple[str, str | None], ...]
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
    emits: list[dict[str, str]]
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
        # ``source_kind`` → list of compiled rules that claim it.
        # Empty here; populated by :meth:`watch_store` once the store
        # contract lands (E.1.11).
        self._by_kind: dict[str, list[CompiledRule]] = {}

    async def evaluate(self, event: TaggerEvent) -> list[TTPTag]:
        """Return zero or more tags produced by rules matching *event*.

        Empty in the contract phase. The impl phase fans the event out
        to ``self._by_kind[event.source_kind]`` and merges results.
        """
        return []

    async def watch_store(self) -> None:
        """Subscribe to per-rule changes and atomically swap them in.

        Reads from :meth:`RuleStore.subscribe_changes`. Each yielded
        change is one rule_id; the engine recompiles that rule alone
        and replaces the corresponding entries in the dispatch index
        in a single assignment. Never returns under normal operation —
        the worker cancels it during shutdown.

        Empty in the contract phase.
        """
        return None


__all__ = [
    "CompiledRule",
    "RuleEngine",
    "RuleSchema",
]
