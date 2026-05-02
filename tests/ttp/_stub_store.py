"""Shared stub :class:`RuleStore` for lifter unit tests.

Tests that exercise :class:`BehavioralLifter` / :class:`IntelLifter` /
:class:`CanaryFingerprintLifter` / :class:`EmailLifter` need a store
reference at construction. Most don't drive the watch loop — they
inject rules into the lifter's :class:`RuleIndex` directly. This stub
provides just enough of the ABC to satisfy construction.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleChange, RuleState, RuleStore


class StubRuleStore(RuleStore):
    """In-memory store with optional preloaded compiled rules."""

    def __init__(
        self,
        compiled: list[CompiledRule] | None = None,
        changes: list[RuleChange] | None = None,
    ) -> None:
        self._compiled = list(compiled or [])
        self._changes = list(changes or [])

    async def load_compiled(self) -> list[CompiledRule]:
        return list(self._compiled)

    async def get_state(self, _rule_id: str) -> RuleState:
        return RuleState()

    async def set_state(self, *_a: Any, **_kw: Any) -> None:
        return None

    def subscribe_changes(self) -> AsyncIterator[RuleChange]:
        changes = list(self._changes)

        async def _gen() -> AsyncIterator[RuleChange]:
            for change in changes:
                yield change

        return _gen()


__all__ = ["StubRuleStore"]
