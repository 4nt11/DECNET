"""Filesystem-backed rule store — reads ``./rules/ttp/`` + inotify watch.

Contract step E.1.11. Bodies raise ``NotImplementedError``; the
constants and platform guard are real so E.2.14b conformance tests
can introspect them today.

Linux-only. The inotify dependency (``asyncinotify`` /
``inotify_simple``) is non-portable by design; macOS / Windows
developers running the test suite use the database backend by
setting ``DECNET_TTP_RULE_STORE_TYPE=database``. The factory check in
:meth:`__init__` enforces this with a one-line operator-readable
error rather than a deep stack trace from the inotify import.

The dependency import is **deferred** to :meth:`subscribe_changes`
during the contract phase so this module is importable without the
inotify package installed. The implementation step (E.3) moves the
import to module top per TTP_TAGGING.md §"Linux-only worker host" —
which is when the dependency is added to ``pyproject.toml``. At
contract phase the codebase compiles, mypy passes, and the constants
below are introspectable for E.2.14b tests without forcing operators
on macOS or CI machines without the lib to install it just to import
the package.
"""
from __future__ import annotations

import re
import sys
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from typing import Final

from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleChange, RuleState, RuleStore


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
# raw ints so this module is importable without the inotify library
# at contract phase. The implementation step replaces these with the
# library-supplied constants on the same module-top import that lands
# the dep — same numeric value, same bitwise OR.
#
# Rationale per TTP_TAGGING.md §E.1.11 "Inotify event mask",
# verified against an actual ``strace`` of vim:
#   IN_CLOSE_WRITE — vim writes in place; dominant save signal.
#   IN_MOVED_TO    — atomic-write editors (gedit, IDEs, deploy
#                    scripts) write tempfile then ``rename()``.
#   IN_CREATE      — brand-new rule file appears (``touch``, ``cp``).
#   IN_DELETE      — rule removed; engine drops it from the dispatch
#                    index and emits ``ttp.rule.reloaded.{rule_id}``.
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


class FilesystemRuleStore(RuleStore):
    """``./rules/ttp/`` + inotify watch + in-process state cache.

    Right for single-host dev — state lost on restart is fine when the
    operator is local. Swarms use :class:`DatabaseRuleStore` so state
    survives restart and propagates across worker hosts.

    Contract phase: every method raises ``NotImplementedError``. The
    impl step (E.3) implements YAML parse + Pydantic validation +
    inotify event loop + atomic per-rule swap into the dispatch index.
    """

    def __init__(self, rules_dir: Path | None = None) -> None:
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
        # In-process state cache — lost on restart by design. The
        # database backend persists across restarts; choosing this
        # backend is choosing the trade-off.
        self._state: dict[str, RuleState] = {}

    async def load_compiled(self) -> list[CompiledRule]:
        raise NotImplementedError(
            "FilesystemRuleStore.load_compiled lands at E.3",
        )

    async def get_state(self, rule_id: str) -> RuleState:
        # Auto-revert expired states is impl-phase behavior; the
        # in-memory dict lookup is the trivial part. Even the lookup
        # belongs to E.3 so the contract surface stays uniformly
        # NotImplementedError across both backends.
        cached = self._state.get(rule_id)
        if cached is None:
            return RuleState()
        if cached.expires_at is not None and cached.expires_at < datetime.now(
            tz=cached.expires_at.tzinfo,
        ):
            # Auto-revert path — full impl (event emission, cache
            # purge) lands at E.3.
            return RuleState()
        return cached

    async def set_state(
        self,
        rule_id: str,
        state: RuleState,
        set_by: str,
    ) -> None:
        raise NotImplementedError(
            "FilesystemRuleStore.set_state lands at E.3",
        )

    def subscribe_changes(self) -> AsyncIterator[RuleChange]:
        raise NotImplementedError(
            "FilesystemRuleStore.subscribe_changes lands at E.3",
        )


__all__ = [
    "FilesystemRuleStore",
    "_INOTIFY_MASK",
    "_VALID_RULE_FILENAME",
]
