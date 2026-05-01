"""Rule store ABC + change/state value types.

Contract step E.1.11. The two backends (``impl/filesystem.py``,
``impl/database.py``) implement :class:`RuleStore` identically — the
E.2.14b conformance suite parametrizes over both and asserts the same
observable behavior.

Three types live here:

* :class:`RuleState` — operator-mutable knobs (enabled / disabled /
  clipped, optional confidence ceiling, optional TTL). Frozen dataclass
  so an entry sitting in an engine dispatch index cannot be torn by an
  in-place mutation.
* :class:`RuleChange` — one event yielded per per-rule change by
  :meth:`RuleStore.subscribe_changes`. The "incremental, never batched"
  property in TTP_TAGGING.md §"Bus topics" is enforced *here*: the
  store yields one change per edit, never an aggregate.
* :class:`RuleStore` — the four-method ABC: load all compiled rules,
  read/write state, subscribe to changes.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, NamedTuple, Union

from decnet.ttp.impl.rule_engine import CompiledRule


# ── Operational state ────────────────────────────────────────────────


@dataclass(frozen=True)
class RuleState:
    """Operator-controlled state stamped onto a :class:`CompiledRule`.

    Frozen so engines reading the value during an evaluate() call see
    a consistent snapshot even if a parallel ``set_state()`` is in
    flight. The default constructor — ``RuleState()`` — is the
    "enabled, no overrides" baseline that
    :meth:`RuleStore.get_state` returns for any rule that has never
    had operational state set.

    Fields mirror the columns of :class:`TTPRuleState` so the
    DB-backed store round-trips without translation.
    """

    state: Literal["enabled", "disabled", "clipped"] = "enabled"
    #: Optional confidence ceiling. ``None`` means "use rule's base".
    #: When set, the engine clamps the emitted tag's confidence
    #: downward (never upward) per TTP_TAGGING.md §"Confidence model".
    confidence_max: float | None = None
    #: Optional TTL on the state itself. When ``expires_at`` is in the
    #: past, the store returns the default enabled state and emits a
    #: ``ttp.rule.state.{rule_id}`` auto-revert event.
    expires_at: datetime | None = None
    #: Free-form operator note (audit trail). Never PII.
    reason: str | None = None
    #: Operator who made the change ("filesystem" / "git" for the FS
    #: store; the admin JWT subject for the DB store).
    set_by: str | None = None
    set_at: datetime | None = None


# ── Change events ────────────────────────────────────────────────────


class RuleChange(NamedTuple):
    """One per-rule change yielded by :meth:`RuleStore.subscribe_changes`.

    The ``change_kind`` discriminator pairs with the union type of
    :attr:`new_value`:

    * ``"definition"`` → ``new_value`` is a :class:`CompiledRule`
      (the YAML changed; engine atomically swaps the entry in its
      dispatch index).
    * ``"state"`` → ``new_value`` is a :class:`RuleState` (only
      operational state changed; the engine restamps the existing
      compiled rule's ``state`` field).

    The store NEVER batches: a 5-rule edit produces 5 :class:`RuleChange`
    instances, not one carrying 5 entries. This is load-bearing — the
    bus per-rule fan-out (``ttp.rule.reloaded.{rule_id}`` /
    ``ttp.rule.state.{rule_id}``) inherits its granularity from this
    iterator.
    """

    change_kind: Literal["definition", "state"]
    rule_id: str
    new_value: Union[CompiledRule, RuleState]


# ── Store ABC ────────────────────────────────────────────────────────


class RuleStore(ABC):
    """Pluggable backend for rule definitions + operational state.

    Implementations land at :mod:`decnet.ttp.store.impl.filesystem`
    and :mod:`decnet.ttp.store.impl.database`. Both must satisfy the
    E.2.14b conformance contract observably — the test suite is
    parametrized over both backends and asserts identical behavior.
    """

    @abstractmethod
    async def load_compiled(self) -> list[CompiledRule]:
        """Return every rule this store knows about, fully compiled.

        Includes operational state stamped onto each rule's ``state``
        field (defaulting to enabled for rules without an explicit
        state row). Called once at engine startup; per-rule edits
        thereafter come through :meth:`subscribe_changes`.
        """

    @abstractmethod
    async def get_state(self, rule_id: str) -> RuleState:
        """Return the current :class:`RuleState` for *rule_id*.

        For an unknown rule_id (no state row exists) MUST return the
        default ``RuleState()`` — never raise, never return ``None``.
        Auto-reverts an expired state to default and emits a
        ``ttp.rule.state.{rule_id}`` event before returning.
        """

    @abstractmethod
    async def set_state(
        self,
        rule_id: str,
        state: RuleState,
        set_by: str,
    ) -> None:
        """Persist the new operational state and emit a change event.

        On a backend failure (DB write error, disk full) MUST raise —
        operational state changes are NOT a tolerated-absence path.
        State drift would be silent and dangerous.
        """

    @abstractmethod
    def subscribe_changes(self) -> AsyncIterator[RuleChange]:
        """Yield one :class:`RuleChange` per per-rule edit.

        Never batches. A 5-rule edit produces 5 yields; a 50-rule
        deploy produces 50. Subscribers (the engine, bus republishers)
        rely on per-rule granularity — collapsing into a batch breaks
        the ``ttp.rule.reloaded.{rule_id}`` topic fan-out.
        """
