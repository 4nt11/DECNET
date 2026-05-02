"""Intel lifter — opportunistic third-party verdict translator (E.3.10).

Reads ``AttackerIntel``-derived payload fields and emits ATT&CK
techniques per Appendix A.10 with per-provider confidence scaling.
Decoupling rule (design doc §"Decoupling: bus-driven, never a hard
dependency", enforced statically by E.2.7): this module imports
NOTHING from ``decnet.intel.{abuseipdb,greynoise,feodo,threatfox}`` —
only ``decnet.web.db.models`` symbols are permitted via ``TTPTag``.

Per-provider null tolerance is the steady state: a fresh attacker with
no intel row yet produces zero tags. A populated AbuseIPDB column with
no GreyNoise still fires AbuseIPDB-driven rules; the lifter never
waits for cross-provider corroboration as a precondition (the
:class:`~decnet.ttp.impl._state.is_active` check + per-rule predicate
gate emission, not provider count).
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any, Final

from decnet.ttp.base import TaggerEvent, TolerantTagger
from decnet.ttp.impl._emit import emit_tags
from decnet.ttp.impl._rule_index import RuleIndex
from decnet.ttp.impl._state import apply_ceiling, is_active
from decnet.ttp.impl.rule_engine import _ATTACK_RELEASE, CompiledRule
from decnet.ttp.store.base import RuleStore
from decnet.web.db.models.ttp import TTPTag, compute_tag_uuid


# AbuseIPDB category → set of technique_ids that fire on it. Derived
# from TTP_TAGGING.md Appendix A.10. Multiple categories can map to the
# same technique (18 + 22 both → T1110); a category may map to multiple
# techniques (14 → T1046 + T1595).
_ABUSEIPDB_CATEGORY_TO_TECHNIQUES: Final[dict[int, frozenset[str]]] = {
    14: frozenset({"T1046", "T1595"}),       # Port Scan
    15: frozenset({"T1190"}),                 # Hacking
    18: frozenset({"T1110"}),                 # Brute-Force
    19: frozenset({"T1595"}),                 # Bad Web Bot
    20: frozenset({"T1078"}),                 # Exploited Host
    21: frozenset({"T1190"}),                 # Web App Attack
    22: frozenset({"T1110"}),                 # SSH
    23: frozenset({"T1190"}),                 # IoT Targeted
    11: frozenset({"T1496", "T1566"}),        # Email Spam (T1566 high-score only)
    10: frozenset({"T1498"}),                 # DDoS
    5: frozenset({"T1110"}),                  # FTP Brute-Force
    17: frozenset({"T1090"}),                 # VPN IP
    9: frozenset({"T1090"}),                  # Open Proxy
}

# Categories where a technique only fires above a confidence-score
# threshold (per A.10: "11 — Email Spam (high score, ≥80) → T1566").
_ABUSEIPDB_HIGH_SCORE_GATED: Final[dict[int, dict[str, int]]] = {
    11: {"T1566": 80},
}


# GreyNoise tag → set of technique_ids the tag warrants.
_GREYNOISE_TAG_TO_TECHNIQUES: Final[dict[str, frozenset[str]]] = {
    "tor_exit_node": frozenset({"T1090"}),
    "ssh_bruteforcer": frozenset({"T1110"}),
    "web_crawler": frozenset({"T1595"}),
    "cobalt_strike": frozenset({"T1071", "T1588"}),
    "metasploit": frozenset({"T1071", "T1588"}),
    "sliver": frozenset({"T1071", "T1588"}),
    "havoc": frozenset({"T1071", "T1588"}),
}

# ThreatFox IOC type → set of technique_ids per A.10.
_THREATFOX_IOC_TO_TECHNIQUES: Final[dict[str, frozenset[str]]] = {
    "botnet_cc": frozenset({"T1071", "T1588"}),
    "c2_server": frozenset({"T1071"}),
    "payload_delivery": frozenset({"T1105", "T1588"}),
    "download_url": frozenset({"T1105"}),
}


# Predicate signature: returns either a list of (technique_id_filter,
# confidence_multiplier, evidence_extra) tuples — one per emit slot the
# rule should fire — or empty list when the rule does not fire.
EmitDecision = list[tuple[str, float, dict[str, Any]]]
Predicate = Callable[[dict[str, Any], dict[str, Any]], EmitDecision]


def _abuseipdb_decisions(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> EmitDecision:
    score = payload.get("abuseipdb_score")
    categories_raw = payload.get("abuseipdb_categories") or payload.get("categories")
    if not isinstance(score, (int, float)):
        return []
    if not isinstance(categories_raw, list) or not categories_raw:
        return []
    categories: list[int] = [c for c in categories_raw if isinstance(c, int)]
    if not categories:
        return []
    # Resolve technique set across all categories present.
    triggered: dict[str, list[int]] = {}
    for cat in categories:
        for tech in _ABUSEIPDB_CATEGORY_TO_TECHNIQUES.get(cat, frozenset()):
            gate = _ABUSEIPDB_HIGH_SCORE_GATED.get(cat, {}).get(tech)
            if gate is not None and score < gate:
                continue
            triggered.setdefault(tech, []).append(cat)
    if not triggered:
        return []
    multiplier = float(score) / 100.0
    return [
        (tech, multiplier, {
            "abuseipdb_categories": cats,
            "abuse_confidence_score": int(score),
        })
        for tech, cats in triggered.items()
    ]


def _greynoise_decisions(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> EmitDecision:
    classification = payload.get("greynoise_classification")
    tags_raw = payload.get("greynoise_tags") or []
    triggered: dict[str, list[str]] = {}
    if classification == "scanner":
        triggered.setdefault("T1595", []).append("scanner")
    if isinstance(tags_raw, list):
        for tag in tags_raw:
            if not isinstance(tag, str):
                continue
            for tech in _GREYNOISE_TAG_TO_TECHNIQUES.get(tag, frozenset()):
                triggered.setdefault(tech, []).append(tag)
    if not triggered:
        return []
    return [
        (tech, 1.0, {
            "greynoise_classification": classification,
            "greynoise_tags": signals,
        })
        for tech, signals in triggered.items()
    ]


def _feodo_decisions(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> EmitDecision:
    if payload.get("feodo_listed") is not True:
        return []
    family = payload.get("malware_family")
    extra: dict[str, Any] = {"feodo_listed": True}
    if isinstance(family, str) and family:
        extra["malware_family"] = family
    # Both T1071 and T1588 emits fire from a Feodo hit.
    return [
        ("T1071", 1.0, extra),
        ("T1588", 1.0, extra),
    ]


def _threatfox_decisions(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> EmitDecision:
    ioc_type = payload.get("ioc_type")
    if not isinstance(ioc_type, str):
        return []
    techs = _THREATFOX_IOC_TO_TECHNIQUES.get(ioc_type, frozenset())
    if not techs:
        return []
    family = payload.get("malware_family")
    extra: dict[str, Any] = {"ioc_type": ioc_type}
    if isinstance(family, str) and family:
        extra["malware_family"] = family
    return [(tech, 1.0, extra) for tech in techs]


def _aggregate_bump_decisions(
    _spec: dict[str, Any], _payload: dict[str, Any],
) -> EmitDecision:
    # R0058 is a bump-only meta-rule (TTP_TAGGING.md §"Initial rule pack"
    # R0058 + commit b819dfe note: confidence < 0.3 drops at the repo
    # layer). The bump-existing semantics need cross-tag access the
    # current TaggerEvent contract doesn't provide; deferred to E.3.14
    # worker bootstrap. Return empty so R0058 is a no-op in v0.
    return []


_PREDICATES: Final[dict[str, Predicate]] = {
    "lifter:intel_abuseipdb": _abuseipdb_decisions,
    "lifter:intel_greynoise": _greynoise_decisions,
    "lifter:intel_feodo": _feodo_decisions,
    "lifter:intel_threatfox": _threatfox_decisions,
    "lifter:intel_aggregate_bump": _aggregate_bump_decisions,
}


class IntelLifter(TolerantTagger):
    name = "intel"
    HANDLES = frozenset({"intel"})
    OWNED_PREFIX: Final[str] = "lifter:intel_"

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
            decisions = handler(rule.match_spec, event.payload)
            if not decisions:
                continue
            out.extend(_emit_filtered(rule, event, decisions))
        return out


def _emit_filtered(
    rule: CompiledRule,
    event: TaggerEvent,
    decisions: EmitDecision,
) -> list[TTPTag]:
    """Fan out only the ``rule.emits`` entries whose technique_id is in
    the predicate's decision set, scaled by the per-decision multiplier
    and stamped with the predicate's evidence extras.

    A rule's YAML may declare ``emits=[T1110, T1190, T1566]`` (the
    universe of possible emissions); the predicate decides which subset
    actually fires for a given payload. This is the lifter analogue of
    "one event maps to many techniques" — except the dispatch is signal-
    driven, not regex-driven.
    """
    decision_by_tech: dict[str, tuple[float, dict[str, Any]]] = {
        tech: (mult, extra) for tech, mult, extra in decisions
    }
    out: list[TTPTag] = []
    base_evidence: dict[str, Any] = {
        field: event.payload.get(field)
        for field in rule.evidence_fields
        if field in event.payload
    }
    for technique_id, sub_technique_id, tactic, base_conf in rule.emits:
        if technique_id not in decision_by_tech:
            continue
        multiplier, extra = decision_by_tech[technique_id]
        evidence = dict(base_evidence)
        evidence.update(extra)
        confidence = apply_ceiling(base_conf * multiplier, rule.state)
        tag_uuid = compute_tag_uuid(
            source_kind=event.source_kind,
            source_id=event.source_id,
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            technique_id=technique_id,
            sub_technique_id=sub_technique_id,
        )
        out.append(TTPTag(
            uuid=tag_uuid,
            source_kind=event.source_kind,
            source_id=event.source_id,
            attacker_uuid=event.attacker_uuid,
            identity_uuid=event.identity_uuid,
            session_id=event.session_id,
            decky_id=event.decky_id,
            tactic=tactic,
            technique_id=technique_id,
            sub_technique_id=sub_technique_id,
            confidence=confidence,
            rule_id=rule.rule_id,
            rule_version=rule.rule_version,
            evidence=evidence,
            attack_release=_ATTACK_RELEASE,
        ))
    return out


__all__ = ["IntelLifter"]


# Suppress unused-import lint; emit_tags is exposed for parity with the
# other lifters even though IntelLifter uses _emit_filtered. Leave the
# import present so future refactors that consolidate emission paths
# don't have to re-add it.
_ = emit_tags
