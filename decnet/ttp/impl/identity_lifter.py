# SPDX-License-Identifier: AGPL-3.0-or-later
"""Identity lifter — cross-attacker identity-rollup tagger.

E.3.13 of ``development/TTP_TAGGING.md``. Owns rules whose
``match.kind`` starts with ``lifter:identity_`` (currently R0003,
password spraying). Reads identity-rollup payloads delivered when
the clusterer publishes ``identity.formed`` / ``identity.merged``:
shape carries ``identity_uuid`` plus aggregate fields the rule's
predicate inspects (``shared_password_hash``, ``account_count``,
member ``attacker_uuid`` set, etc.).

Tags emitted by this lifter carry ``identity_uuid`` populated and
``attacker_uuid=NULL`` per the design doc's "identity rollup"
worked example — the tag belongs to the Identity, not to any one
member IP.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.ttp.impl._emit import emit_tags
from decnet.ttp.impl._rule_index import RuleIndex
from decnet.ttp.impl._state import is_active
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleStore
from decnet.web.db.models.ttp import TTPTag


# Predicate returns supplemental evidence on a fire (may be empty),
# or ``None`` when the rule does not fire on this event.
Predicate = Callable[[dict[str, Any], dict[str, Any]], "dict[str, Any] | None"]


def _p_password_spraying(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    """R0003 — same password tried across many accounts.

    Predicate fires when the clusterer-supplied ``account_count``
    meets or exceeds the rule's ``account_threshold`` AND a
    ``shared_password_hash`` is present (so the tag points at a
    specific reused-password observation, not just a count). The
    threshold defaults to 1 only as a safety net — production
    YAML pins ``account_threshold: 3``.
    """
    shared_hash = payload.get("shared_password_hash")
    account_count = payload.get("account_count")
    if not isinstance(shared_hash, str) or not shared_hash:
        return None
    if not isinstance(account_count, int):
        return None
    threshold = spec.get("account_threshold", 1)
    if not isinstance(threshold, int):
        return None
    if account_count < threshold:
        return None
    return {
        "shared_password_hash": shared_hash,
        "account_count": account_count,
    }


_PREDICATES: Final[dict[str, Predicate]] = {
    "lifter:identity_password_spraying": _p_password_spraying,
}


class IdentityLifter(TolerantTagger):
    name = "identity"
    HANDLES = frozenset({"identity"})
    OWNED_PREFIX: Final[str] = "lifter:identity_"

    def __init__(self, store: RuleStore) -> None:
        self._store = store
        self._index = RuleIndex()

    @classmethod
    def _owns(cls, rule: CompiledRule) -> bool:
        kind = rule.match_spec.get("kind", "")
        return isinstance(kind, str) and kind.startswith(cls.OWNED_PREFIX)

    async def watch_store(self) -> None:
        await self._index.watch(self._store, predicate=self._owns)

    async def _tag_impl(self, event: TaggerEvent) -> list[TTPTag]:
        out: list[TTPTag] = []
        for rule in self._index.values():
            if event.source_kind not in rule.applies_to:
                continue
            if not is_active(rule.state):
                continue
            kind = rule.match_spec.get("kind", "")
            handler = _PREDICATES.get(kind)
            if handler is None:
                continue
            extra = handler(rule.match_spec, event.payload)
            if extra is None:
                continue
            evidence: dict[str, Any] = {
                field: event.payload.get(field)
                for field in rule.evidence_fields
                if field in event.payload
            }
            evidence.update(extra)
            # Identity-rollup tags carry identity_uuid, never an
            # attacker_uuid — null out whatever the upstream event
            # carried so the worked-example invariant holds.
            rolled = event._replace(attacker_uuid=None)
            out.extend(emit_tags(rule, rolled, evidence))
        return out


__all__ = ["IdentityLifter"]
