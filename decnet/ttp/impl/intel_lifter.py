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
# from TTP_TAGGING.md Appendix A.10 (post 2026-05-02 ship-time audit).
# Category code names are AbuseIPDB's canonical taxonomy at
# https://www.abuseipdb.com/categories — kept verbatim in the comment so
# the next quarterly drift check (development/DEBT.md DEBT-048) can
# diff cheaply. Cat 4 (DDoS Attack) and 10 (Web Spam) and 12 (Blog
# Spam) are intentionally unmapped — design doc §A.10 marks
# DDoS-without-protocol as too muddy for v0, and CMS spam has no clean
# ATT&CK fit at the IP layer.
_ABUSEIPDB_CATEGORY_TO_TECHNIQUES: Final[dict[int, frozenset[str]]] = {
    5: frozenset({"T1110"}),                  # FTP Brute-Force
    7: frozenset({"T1566"}),                  # Phishing
    9: frozenset({"T1090"}),                  # Open Proxy
    11: frozenset({"T1496", "T1566"}),        # Email Spam (T1566 high-score only)
    13: frozenset({"T1090"}),                 # VPN IP
    14: frozenset({"T1046", "T1595"}),        # Port Scan
    15: frozenset({"T1190"}),                 # Hacking
    16: frozenset({"T1190"}),                 # SQL Injection
    17: frozenset({"T1566"}),                 # Spoofing (email-sender)
    18: frozenset({"T1110"}),                 # Brute-Force
    19: frozenset({"T1595"}),                 # Bad Web Bot
    20: frozenset({"T1078"}),                 # Exploited Host
    21: frozenset({"T1190"}),                 # Web App Attack
    22: frozenset({"T1110"}),                 # SSH
    23: frozenset({"T1190"}),                 # IoT Targeted
}

# Categories where a technique only fires above a confidence-score
# threshold (per A.10: "11 — Email Spam (high score, ≥80) → T1566").
_ABUSEIPDB_HIGH_SCORE_GATED: Final[dict[int, dict[str, int]]] = {
    11: {"T1566": 80},
}


# GreyNoise tag → set of technique_ids the tag warrants. Note: the
# Community endpoint does not return tags today — these fire only when
# operators wire a non-Community provider that does. Kept canonical so
# the upgrade path is just a column populate, not a code change.
_GREYNOISE_TAG_TO_TECHNIQUES: Final[dict[str, frozenset[str]]] = {
    "tor_exit_node": frozenset({"T1090"}),
    "ssh_bruteforcer": frozenset({"T1110"}),
    "web_crawler": frozenset({"T1595"}),
    "cobalt_strike": frozenset({"T1071", "T1588"}),
    "metasploit": frozenset({"T1071", "T1588"}),
    "sliver": frozenset({"T1071", "T1588"}),
    "havoc": frozenset({"T1071", "T1588"}),
}

# Confidence multiplier when GreyNoise reports ``classification ==
# "malicious"`` without a specific tag we recognise. The bare
# classification is real signal but weaker than a tag — half-confidence
# keeps the floor honest.
_GREYNOISE_MALICIOUS_BARE_MULT: Final[float] = 0.5

# ThreatFox THREAT TYPE (NOT ioc_type — that was the v1 ship-time bug)
# → set of technique_ids. Per ThreatFox's API the canonical taxonomy
# field is ``threat_type`` ∈ {botnet_cc, payload_delivery, payload,
# cc_skimming}; ``ioc_type`` is the indicator format (url, domain,
# md5_hash, …) and carries no ATT&CK signal.
_THREATFOX_THREAT_TYPE_TO_TECHNIQUES: Final[dict[str, frozenset[str]]] = {
    "botnet_cc": frozenset({"T1071", "T1588"}),
    "payload_delivery": frozenset({"T1105", "T1588"}),
    "payload": frozenset({"T1588"}),
    "cc_skimming": frozenset({"T1056"}),
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
    """Decide GreyNoise emissions.

    Three signal lanes:
    * ``classification == "scanner"`` — full-strength T1595 (kept for
      compatibility with non-Community provider plans that surface
      this verdict; the Community endpoint reports {malicious, benign,
      suspicious, unknown} only).
    * Specific recognised tag → its mapped technique(s) at 1.0×.
    * Bare ``classification == "malicious"`` with no recognised tag →
      T1071 at half multiplier (post-audit decision: the verdict is
      real but unspecific). The bare-malicious lane is suppressed when
      a tag already fired on T1071 to avoid double-stamping.
    """
    classification = payload.get("greynoise_classification")
    tags_raw = payload.get("greynoise_tags") or []
    # Per-technique evidence accumulator — maps technique_id to the
    # signals that triggered it AND the multiplier to apply (max wins
    # if multiple lanes hit the same technique).
    triggered: dict[str, tuple[float, list[str]]] = {}

    def _bump(tech: str, mult: float, signal: str) -> None:
        existing = triggered.get(tech)
        if existing is None:
            triggered[tech] = (mult, [signal])
            return
        old_mult, signals = existing
        signals.append(signal)
        if mult > old_mult:
            triggered[tech] = (mult, signals)

    if classification == "scanner":
        _bump("T1595", 1.0, "scanner")
    if isinstance(tags_raw, list):
        for tag in tags_raw:
            if not isinstance(tag, str):
                continue
            for tech in _GREYNOISE_TAG_TO_TECHNIQUES.get(tag, frozenset()):
                _bump(tech, 1.0, tag)
    if classification == "malicious" and "T1071" not in triggered:
        _bump("T1071", _GREYNOISE_MALICIOUS_BARE_MULT, "malicious")
    if not triggered:
        return []
    return [
        (tech, mult, {
            "greynoise_classification": classification,
            "greynoise_tags": signals,
        })
        for tech, (mult, signals) in triggered.items()
    ]


def _feodo_decisions(
    _spec: dict[str, Any], payload: dict[str, Any],
) -> EmitDecision:
    if payload.get("feodo_listed") is not True:
        return []
    family = (
        payload.get("feodo_malware_family")
        or payload.get("malware_family")
    )
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
    """ThreatFox dispatch keys on ``threat_type`` (canonical taxonomy)
    not ``ioc_type`` — the v1 ship-time mapping had it backwards.

    Accepts either ``threatfox_threat_types`` (list, preferred — comes
    from the bus payload built by the intel worker) or a singular
    ``threat_type``/``ioc_type`` field for legacy callers and tests.
    The lifter is tolerant by contract; missing inputs produce zero
    emissions, never an error.
    """
    threat_types_raw = (
        payload.get("threatfox_threat_types")
        or payload.get("threat_type")
    )
    threat_types: list[str] = []
    if isinstance(threat_types_raw, list):
        threat_types = [t for t in threat_types_raw if isinstance(t, str)]
    elif isinstance(threat_types_raw, str) and threat_types_raw:
        threat_types = [threat_types_raw]

    triggered: dict[str, list[str]] = {}
    for tt in threat_types:
        for tech in _THREATFOX_THREAT_TYPE_TO_TECHNIQUES.get(tt, frozenset()):
            triggered.setdefault(tech, []).append(tt)
    if not triggered:
        return []

    families_raw = (
        payload.get("threatfox_malware_families")
        or payload.get("malware_family")
    )
    families: list[str] = []
    if isinstance(families_raw, list):
        families = [f for f in families_raw if isinstance(f, str)]
    elif isinstance(families_raw, str) and families_raw:
        families = [families_raw]
    ioc_types_raw = payload.get("threatfox_ioc_types")
    ioc_types: list[str] = (
        [i for i in ioc_types_raw if isinstance(i, str)]
        if isinstance(ioc_types_raw, list) else []
    )

    return [
        (tech, 1.0, {
            "threat_types": signals,
            **({"malware_families": families} if families else {}),
            **({"ioc_types": ioc_types} if ioc_types else {}),
        })
        for tech, signals in triggered.items()
    ]


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


def all_emitted_technique_ids() -> frozenset[str]:
    """Every technique ID this lifter could emit, drawn from all four provider tables.

    Used by :func:`validate_against_attack_bundle` (and
    :mod:`tests.ttp.test_attack_catalog`-adjacent tests) to assert that
    every provider-driven emission resolves in the loaded ATT&CK STIX
    bundle. Includes the bare-classification emissions in
    ``_greynoise_decisions`` and the unconditional emissions in
    ``_feodo_decisions`` — those don't appear in the lookup tables
    above because they're decision-flow constants, not table entries.
    """
    ids: set[str] = set()
    for techs in _ABUSEIPDB_CATEGORY_TO_TECHNIQUES.values():
        ids.update(techs)
    for techs in _GREYNOISE_TAG_TO_TECHNIQUES.values():
        ids.update(techs)
    for techs in _THREATFOX_THREAT_TYPE_TO_TECHNIQUES.values():
        ids.update(techs)
    # Decision-flow constants (see _greynoise_decisions, _feodo_decisions).
    ids.update({"T1071", "T1595", "T1588"})
    return frozenset(ids)


def validate_against_attack_bundle() -> None:
    """Assert every technique ID this lifter could emit resolves in the loaded ATT&CK STIX bundle."""
    from decnet.ttp.attack_stix import assert_known_technique_ids

    assert_known_technique_ids(
        list(all_emitted_technique_ids()),
        source="decnet.ttp.impl.intel_lifter",
    )


__all__ = ["IntelLifter", "all_emitted_technique_ids", "validate_against_attack_bundle"]


# Suppress unused-import lint; emit_tags is exposed for parity with the
# other lifters even though IntelLifter uses _emit_filtered. Leave the
# import present so future refactors that consolidate emission paths
# don't have to re-add it.
_ = emit_tags
