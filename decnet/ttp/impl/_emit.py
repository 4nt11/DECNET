# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared TTPTag emission helper used by per-source lifters.

The rule engine assembles a tag inline inside ``_evaluate_rules``; the
four lifters (E.3.9–E.3.13) emit tags from the same shape but never
go through the engine's regex matcher. Pulling the assembly into one
helper keeps the ``compute_tag_uuid`` call signature, the
``apply_ceiling`` clamp, and the ``attack_release`` stamping
single-sourced.
"""
from __future__ import annotations

from typing import Any

from decnet.ttp.attack_stix import mitre_url_for
from decnet.ttp.base import TaggerEvent
from decnet.ttp.impl._state import apply_ceiling
from decnet.ttp.impl.rule_engine import _ATTACK_RELEASE, CompiledRule
from decnet.web.db.models.ttp import TTPTag, compute_tag_uuid


def emit_tags(
    rule: CompiledRule,
    event: TaggerEvent,
    evidence: dict[str, Any],
) -> list[TTPTag]:
    """Materialise one TTPTag per ``rule.emits`` entry.

    Caller is responsible for having checked ``is_active(rule.state)``
    and the per-rule predicate before calling. ``evidence`` is the
    fully-assembled evidence dict the lifter wants on each emitted
    tag — caller honours ``rule.evidence_fields`` and any per-rule
    PII discipline (e.g. EmailEvidence) before passing it in.

    The tag UUID is deterministic over (source_kind, source_id, rule_id,
    rule_version, technique_id, sub_technique_id). Replay-safe: a worker
    re-processing the same source events writes idempotent rows.
    """
    out: list[TTPTag] = []
    for technique_id, sub_technique_id, tactic, base_conf in rule.emits:
        confidence = apply_ceiling(base_conf, rule.state)
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
            evidence=dict(evidence),
            attack_release=_ATTACK_RELEASE,
            mitre_url=mitre_url_for(sub_technique_id or technique_id),
        ))
    return out


__all__ = ["emit_tags"]
