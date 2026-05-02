"""Behavioral lifter — derives techniques from cross-event session signal.

E.3.9 of ``development/TTP_TAGGING.md``. Owns YAML rules R0031–R0040 by
``match.kind`` prefix ``lifter:behavioral_``. Each rule's predicate runs
against the upstream-pre-shaped session aggregate carried in
``TaggerEvent.payload``; the lifter never reaches into the database
directly. Sibling-worker absence (no ``AttackerBehavior`` row, no
session aggregate) yields ``[]`` per the
:class:`~decnet.ttp.base.TolerantTagger` contract.

The lifter holds its own :class:`~decnet.ttp.impl._rule_index.RuleIndex`
filtered by ``OWNED_PREFIX`` so operator state changes (disable / clip
/ TTL) reach lifter-bound rules through the same atomic-swap path the
engine uses — see TTP_TAGGING.md §"Atomic swap".
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, Final

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.ttp.impl._emit import emit_tags
from decnet.ttp.impl._rule_index import RuleIndex
from decnet.ttp.impl._state import is_active
from decnet.ttp.impl.rule_engine import CompiledRule
from decnet.ttp.store.base import RuleStore
from decnet.web.db.models.ttp import TTPTag


# A predicate returns the supplemental evidence dict on a fire (may be
# empty), or ``None`` when the rule does not fire on this event.
Predicate = Callable[[dict[str, Any], dict[str, Any]], "dict[str, Any] | None"]


# ── Per-rule predicates ─────────────────────────────────────────────


def _p_beaconing(spec: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any] | None:
    interval = payload.get("beacon_interval_s")
    jitter = payload.get("beacon_jitter_pct")
    if not isinstance(interval, (int, float)) or not isinstance(jitter, (int, float)):
        return None
    if interval < float(spec.get("min_interval_s", 0)):
        return None
    if jitter > float(spec.get("max_jitter_pct", 1.0)):
        return None
    return {}


def _p_data_destruction(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    haystack = payload.get("op_text") or payload.get("command_text") or ""
    if not isinstance(haystack, str):
        return None
    patterns = spec.get("patterns", [])
    if not isinstance(patterns, list):
        return None
    for pat in patterns:
        if not isinstance(pat, str):
            continue
        try:
            if re.search(pat, haystack):
                return {"matched_op": pat}
        except re.error:
            continue
    return None


_BTC_RE = re.compile(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b")
_XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")


def _p_ransom_note(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    text = payload.get("body_text") or payload.get("note_text") or ""
    if not isinstance(text, str) or not text:
        return None
    keywords = spec.get("payment_keywords", [])
    matched_keywords = [
        k for k in keywords
        if isinstance(k, str) and k.lower() in text.lower()
    ]
    if not matched_keywords:
        return None
    if spec.get("require_btc_or_xmr"):
        btc = _BTC_RE.search(text)
        xmr = _XMR_RE.search(text)
        if not (btc or xmr):
            return None
        addr = (btc or xmr)
        return {
            "btc_address": addr.group(0) if addr else "",
            "matched_keywords": matched_keywords,
        }
    return {"matched_keywords": matched_keywords}


def _p_exfil_over_web(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    bytes_out = payload.get("bytes_out")
    request_count = payload.get("request_count")
    min_bytes = float(spec.get("min_payload_bytes", 0))
    min_reqs = int(spec.get("request_threshold", 0))
    bytes_hit = isinstance(bytes_out, (int, float)) and bytes_out >= min_bytes
    req_hit = isinstance(request_count, int) and request_count >= min_reqs
    if not (bytes_hit or req_hit):
        return None
    return {}


def _p_db_mass_read(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    rows = payload.get("rows_read")
    nbytes = payload.get("bytes_read")
    min_rows = int(spec.get("min_rows", 0))
    min_bytes = int(spec.get("min_bytes", 0))
    rows_hit = isinstance(rows, int) and rows >= min_rows
    bytes_hit = isinstance(nbytes, (int, float)) and nbytes >= min_bytes
    if not (rows_hit or bytes_hit):
        return None
    return {}


def _path_match(
    spec: dict[str, Any], payload: dict[str, Any], key: str = "paths",
) -> dict[str, Any] | None:
    path = (
        payload.get("matched_path")
        or payload.get("request_path")
        or payload.get("path")
        or ""
    )
    if not isinstance(path, str) or not path:
        return None
    patterns = spec.get(key, [])
    if not isinstance(patterns, list):
        return None
    for pat in patterns:
        if not isinstance(pat, str):
            continue
        try:
            if re.search(pat, path):
                return {"matched_path": path}
        except re.error:
            continue
    return None


def _p_credentials_in_files(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    return _path_match(spec, payload, key="paths")


def _p_k8s_sa_token(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    return _path_match(spec, payload, key="paths")


def _p_docker_escape(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    observed = payload.get("signals")
    if not isinstance(observed, list):
        return None
    wanted = spec.get("signals", [])
    if not isinstance(wanted, list):
        return None
    observed_set = {s for s in observed if isinstance(s, str)}
    for sig in wanted:
        if isinstance(sig, str) and sig in observed_set:
            return {"matched_signal": sig}
    return None


def _p_llmnr_poisoning(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    if payload.get("llmnr_poisoned") is True:
        return {}
    if isinstance(payload.get("llmnr_poison_count"), int) and payload["llmnr_poison_count"] >= 1:
        return {}
    return None


def _p_tftp_router_config(
    spec: dict[str, Any], payload: dict[str, Any],
) -> dict[str, Any] | None:
    fname = payload.get("tftp_filename") or ""
    if not isinstance(fname, str) or not fname:
        return None
    patterns = spec.get("filename_patterns", [])
    if not isinstance(patterns, list):
        return None
    for pat in patterns:
        if not isinstance(pat, str):
            continue
        try:
            if re.search(pat, fname):
                return {}
        except re.error:
            continue
    return None


_PREDICATES: Final[dict[str, Predicate]] = {
    "lifter:behavioral_beaconing": _p_beaconing,
    "lifter:behavioral_data_destruction": _p_data_destruction,
    "lifter:behavioral_ransom_note": _p_ransom_note,
    "lifter:behavioral_exfil_over_web": _p_exfil_over_web,
    "lifter:behavioral_db_mass_read": _p_db_mass_read,
    "lifter:behavioral_credentials_in_files": _p_credentials_in_files,
    "lifter:behavioral_k8s_sa_token": _p_k8s_sa_token,
    "lifter:behavioral_docker_escape": _p_docker_escape,
    "lifter:behavioral_llmnr_poisoning": _p_llmnr_poisoning,
    "lifter:behavioral_tftp_router_config": _p_tftp_router_config,
}


# ── Lifter ──────────────────────────────────────────────────────────


class BehavioralLifter(TolerantTagger):
    name = "behavioral"
    #: BehavioralLifter consumes session-rolled events plus a few cross-
    #: cutting source kinds (``email`` for R0033 ransom-note pattern,
    #: ``http_request`` for R0036/R0037 path-match rules). The set
    #: matches the union of ``applies_to`` across R0031–R0040.
    HANDLES = frozenset({"session", "email", "http_request"})
    OWNED_PREFIX: Final[str] = "lifter:behavioral_"

    def __init__(self, store: RuleStore) -> None:
        self._store = store
        self._index = RuleIndex()

    @classmethod
    def _owns(cls, rule: CompiledRule) -> bool:
        kind = rule.match_spec.get("kind", "")
        return isinstance(kind, str) and kind.startswith(cls.OWNED_PREFIX)

    async def watch_store(self) -> None:
        """Hydrate + drain rule changes for the rules this lifter owns."""
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


__all__ = ["BehavioralLifter"]
