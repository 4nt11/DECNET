"""TTP rule store — pluggable backend for rule definitions + state.

Contract step E.1.11 of ``development/TTP_TAGGING.md``. Two backends
ship:

* :class:`FilesystemRuleStore` — reads ``./rules/ttp/`` at projroot,
  inotify-watches for hot-reload, holds operational state in-process.
  Linux-only (the inotify dependency is non-portable by design).
* :class:`DatabaseRuleStore` — mirrors rule content into ``ttp_rule``
  with state in ``ttp_rule_state``; survives restart and propagates
  to every worker in a swarm.

Selection via ``DECNET_TTP_RULE_STORE_TYPE`` (default ``"filesystem"``).
"""
from __future__ import annotations

from decnet.ttp.store.base import RuleChange, RuleState, RuleStore
from decnet.ttp.store.factory import get_rule_store

__all__ = [
    "RuleChange",
    "RuleState",
    "RuleStore",
    "get_rule_store",
]
