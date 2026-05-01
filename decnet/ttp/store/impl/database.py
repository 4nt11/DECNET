"""Database-backed rule store — ``ttp_rule`` + ``ttp_rule_state``.

Contract step E.1.11. Bodies raise ``NotImplementedError``; the
backing tables (:class:`TTPRule`, :class:`TTPRuleState`) shipped at
E.1.1.

Right for swarm: master syncs filesystem changes into ``ttp_rule``,
workers tail the DB, state in ``ttp_rule_state`` survives restart and
propagates to every worker. Pick via
``DECNET_TTP_RULE_STORE_TYPE=database``.

No platform guard — works on macOS / Windows where the filesystem
backend's inotify dependency is unavailable.
"""
from __future__ import annotations

from collections.abc import AsyncIterator

from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleChange, RuleState, RuleStore


class DatabaseRuleStore(RuleStore):
    """``ttp_rule`` content + ``ttp_rule_state`` operational state.

    Contract phase: every method raises ``NotImplementedError``. The
    impl step (E.3) implements DB-tail subscription + master-side
    filesystem→DB sync. Worker-side tailing reads via the existing
    repository pattern; the master's filesystem-watch sync is
    structurally a delta from :class:`FilesystemRuleStore` plus a
    ``ttp_rule`` upsert.
    """

    async def load_compiled(self) -> list[CompiledRule]:
        raise NotImplementedError(
            "DatabaseRuleStore.load_compiled lands at E.3",
        )

    async def get_state(self, rule_id: str) -> RuleState:
        raise NotImplementedError(
            "DatabaseRuleStore.get_state lands at E.3",
        )

    async def set_state(
        self,
        rule_id: str,
        state: RuleState,
        set_by: str,
    ) -> None:
        raise NotImplementedError(
            "DatabaseRuleStore.set_state lands at E.3",
        )

    def subscribe_changes(self) -> AsyncIterator[RuleChange]:
        raise NotImplementedError(
            "DatabaseRuleStore.subscribe_changes lands at E.3",
        )


__all__ = ["DatabaseRuleStore"]
