"""Hot-swappable rule registry shared by RuleEngine and per-source lifters.

The dispatch index originally lived inline on
:class:`~decnet.ttp.impl.rule_engine.RuleEngine`. E.3.9 adds four
per-source lifters that need the same install / evict / state-restamp
atomic-swap protocol; pulling it into one helper keeps the contract
single-sourced.

Atomicity invariant (TTP_TAGGING.md §"Atomic swap" / E.2.14b): a rule
sitting in the index must never be torn mid-evaluate. Mutations
replace dict entries with fresh lists / fresh
:class:`~decnet.ttp.impl.rule_engine.CompiledRule` tuples — never
in-place edits. Single dict assignments are GIL-atomic to readers.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING

from decnet.logging import get_logger

if TYPE_CHECKING:
    from decnet.ttp.impl.rule_engine import CompiledRule
    from decnet.ttp.store.base import RuleChange, RuleStore


_log = get_logger("ttp.index")


class RuleIndex:
    """Owns ``rule_id -> CompiledRule`` plus a ``source_kind -> [rules]`` index.

    Consumers:

    * :class:`RuleEngine` — uses :meth:`by_kind` to dispatch evaluate().
    * Per-source lifters (E.3.9–E.3.13) — use :meth:`get` and
      :meth:`values` to consume rules they own (filtered via the
      ``predicate`` passed to :meth:`watch`).
    """

    def __init__(self) -> None:
        # source_kind -> list of compiled rules that claim it.
        self._by_kind: dict[str, list["CompiledRule"]] = {}
        # rule_id -> compiled rule (mirror; used for state restamp).
        self._by_rule: dict[str, "CompiledRule"] = {}

    # ── Read API ────────────────────────────────────────────────────

    def by_kind(self, source_kind: str) -> list["CompiledRule"]:
        return self._by_kind.get(source_kind, [])

    def get(self, rule_id: str) -> "CompiledRule | None":
        return self._by_rule.get(rule_id)

    def values(self) -> Iterable["CompiledRule"]:
        return self._by_rule.values()

    # ── Mutation API (atomic-swap) ──────────────────────────────────

    def install(self, rule: "CompiledRule") -> None:
        """Atomic-swap install of one compiled rule.

        Empty ``applies_to`` AND empty ``emits`` is the deletion sentinel
        used by both store backends — drop the rule from the index
        instead of registering a no-op entry.
        """
        if not rule.applies_to and not rule.emits:
            self.evict(rule.rule_id)
            return
        self._by_rule[rule.rule_id] = rule
        for kind in rule.applies_to:
            current = self._by_kind.get(kind, [])
            replaced = [r for r in current if r.rule_id != rule.rule_id]
            replaced.append(rule)
            # Single dict assignment — GIL-atomic to readers.
            self._by_kind[kind] = replaced

    def evict(self, rule_id: str) -> None:
        existing = self._by_rule.pop(rule_id, None)
        if existing is None:
            return
        for kind in existing.applies_to:
            current = self._by_kind.get(kind, [])
            replaced = [r for r in current if r.rule_id != rule_id]
            self._by_kind[kind] = replaced

    def apply_change(
        self, change: "RuleChange", state_cls: type
    ) -> None:
        """Apply one :class:`RuleChange` to the index.

        ``state_cls`` is :class:`RuleState`; passed in to avoid a
        runtime-circular import — the store package imports from this
        one transitively.
        """
        from decnet.ttp.impl.rule_engine import CompiledRule  # noqa: PLC0415

        if change.change_kind == "definition":
            value = change.new_value
            if isinstance(value, CompiledRule):
                self.install(value)
            return
        # state change
        existing = self._by_rule.get(change.rule_id)
        if existing is None or not isinstance(change.new_value, state_cls):
            return
        new_state = change.new_value
        # NamedTuple._replace returns a fresh frozen tuple — single
        # dict assignment swaps it in atomically.
        restamped = existing._replace(state=new_state)  # type: ignore[arg-type]
        self._by_rule[change.rule_id] = restamped
        for kind in restamped.applies_to:
            current = self._by_kind.get(kind, [])
            replaced = [r for r in current if r.rule_id != change.rule_id]
            replaced.append(restamped)
            self._by_kind[kind] = replaced

    # ── Lifecycle ───────────────────────────────────────────────────

    async def hydrate_from(
        self,
        store: "RuleStore",
        predicate: Callable[["CompiledRule"], bool] | None = None,
    ) -> None:
        """Load every compiled rule from *store* and install matching ones.

        ``predicate`` filters; engine omits it (installs everything),
        lifters pass a ``match.kind`` prefix check.
        """
        compiled = await store.load_compiled()
        for rule in compiled:
            if predicate is not None and not predicate(rule):
                continue
            self.install(rule)

    async def watch(
        self,
        store: "RuleStore",
        predicate: Callable[["CompiledRule"], bool] | None = None,
    ) -> None:
        """Hydrate once + drain ``subscribe_changes`` forever.

        Cancellation-safe: an :class:`asyncio.CancelledError` from the
        outer task propagates cleanly. Per-change application errors
        log and continue — one bad rule edit must not stall the stream.
        """
        from decnet.ttp.store.base import RuleState  # noqa: PLC0415

        await self.hydrate_from(store, predicate=predicate)
        async for change in store.subscribe_changes():
            if predicate is not None:
                # For state changes the value is a RuleState (no
                # match_spec to inspect); always apply when the rule
                # is already in the index, otherwise skip.
                if change.change_kind == "state":
                    if change.rule_id not in self._by_rule:
                        continue
                else:
                    value = change.new_value
                    # Definition changes carry a CompiledRule; skip
                    # ones the predicate doesn't claim. A previously-
                    # owned rule whose YAML moved out of our ownership
                    # gets evicted explicitly.
                    from decnet.ttp.impl.rule_engine import (  # noqa: PLC0415
                        CompiledRule,
                    )
                    if isinstance(value, CompiledRule) and not predicate(value):
                        if change.rule_id in self._by_rule:
                            self.evict(change.rule_id)
                        continue
            try:
                self.apply_change(change, RuleState)
            except Exception:  # noqa: BLE001
                _log.exception(
                    "ttp.index: rule change apply failed rule_id=%s",
                    change.rule_id,
                )


__all__ = ["RuleIndex"]
