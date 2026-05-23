# SPDX-License-Identifier: AGPL-3.0-or-later
"""Credential lifter — credential-capture / reuse / brute-force tagger.

E.3.13 of ``development/TTP_TAGGING.md``. Owns rules whose
``match.kind`` starts with ``lifter:credential_``. Currently:

* R0001 ``lifter:credential_auth_brute_generic`` — repeated failed
  auth across services / accounts on a single attacker.
* R0002 ``lifter:credential_password_guessing`` — many passwords
  tried against one username.
* R0004 ``lifter:credential_reuse`` — credential observed re-used
  across attackers (``CredentialReuse`` row on the bus).
* R0005 ``lifter:credential_valid_account_use`` — successful login
  on an account previously brute-forced (``T1078`` valid account).
* R0006 ``lifter:credential_default_credentials`` — login pair
  matches a known default (``root/root``, ``admin/admin``, …).

Tolerates absence by inheriting :class:`TolerantTagger` — the
reuse-correlator is a sibling worker, not a hard dependency.
Predicates accept payloads from either ``credential.reuse.detected``
events (``credential`` source kind) or session-aggregated auth
streams (``auth_attempt`` source kind); each rule's ``applies_to``
gates the dispatch.
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


Predicate = Callable[[dict[str, Any], dict[str, Any]], "dict[str, Any] | None"]


def _p_auth_brute_generic(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    """R0001 — total auth failures over a window cross a threshold."""
    fail_count = payload.get("fail_count")
    if not isinstance(fail_count, int):
        return None
    threshold = spec.get("fail_threshold", 5)
    if not isinstance(threshold, int) or fail_count < threshold:
        return None
    out: dict[str, Any] = {"fail_count": fail_count}
    service = payload.get("service")
    if isinstance(service, str) and service:
        out["service"] = service
    return out


def _p_password_guessing(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    """R0002 — many distinct passwords tried against one username."""
    pw_count = payload.get("password_count")
    username = payload.get("username")
    if not isinstance(pw_count, int) or not isinstance(username, str):
        return None
    if not username:
        return None
    threshold = spec.get("pw_threshold", 5)
    if not isinstance(threshold, int) or pw_count < threshold:
        return None
    return {"username": username, "password_count": pw_count}


def _p_credential_reuse(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    """R0004 — ``CredentialReuse`` row indicates a hash seen on ≥2 attackers."""
    cred_hash = payload.get("credential_hash")
    reuse_count = payload.get("reuse_count")
    if not isinstance(cred_hash, str) or not cred_hash:
        return None
    if not isinstance(reuse_count, int) or reuse_count < 1:
        return None
    return {"credential_hash": cred_hash, "reuse_count": reuse_count}


def _p_valid_account_use(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    """R0005 — successful login on a previously-brute-forced account."""
    if payload.get("result") != "success":
        return None
    if spec.get("require_prior_brute"):
        if payload.get("prior_brute") is not True:
            return None
    out: dict[str, Any] = {}
    username = payload.get("username")
    service = payload.get("service")
    if isinstance(username, str) and username:
        out["username"] = username
    if isinstance(service, str) and service:
        out["service"] = service
    return out


def _p_default_credentials(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    """R0006 — login pair matches one of the known-default pairs."""
    username = payload.get("username")
    password = payload.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        return None
    pairs = spec.get("pairs", [])
    if not isinstance(pairs, list):
        return None
    for pair in pairs:
        if not isinstance(pair, list) or len(pair) != 2:
            continue
        u, p = pair
        if not isinstance(u, str) or not isinstance(p, str):
            continue
        if username == u and password == p:
            out: dict[str, Any] = {"username": username}
            service = payload.get("service")
            if isinstance(service, str) and service:
                out["service"] = service
            return out
    return None


_PREDICATES: Final[dict[str, Predicate]] = {
    "lifter:credential_auth_brute_generic": _p_auth_brute_generic,
    "lifter:credential_password_guessing": _p_password_guessing,
    "lifter:credential_reuse": _p_credential_reuse,
    "lifter:credential_valid_account_use": _p_valid_account_use,
    "lifter:credential_default_credentials": _p_default_credentials,
}


class CredentialLifter(TolerantTagger):
    name = "credential"
    #: Auth-attempt streams plus credential-reuse events both flow
    #: through this lifter — the per-rule ``applies_to`` filter
    #: routes each rule to the correct source kind.
    HANDLES = frozenset({"credential", "auth_attempt"})
    OWNED_PREFIX: Final[str] = "lifter:credential_"

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
            out.extend(emit_tags(rule, event, evidence))
        return out


__all__ = ["CredentialLifter"]
