"""
Unified Kill Chain phase vocabulary (Pols, 2017).

Used as the canonical phase enum for campaign clustering and (eventually)
the MITRE ATT&CK / TTPs-tagging worker. UKC tactic names map cleanly onto
ATT&CK tactics, so emitting these labels in synthetic data and runtime
phase inference avoids a renaming pass when TTP-tagging lands.

A honeypot does not observe the entire chain. Pre-target phases (OSINT
reconnaissance, resource development, weaponization, social engineering)
happen before any decky is touched. The DSL allows the full enum so a
campaign spec can describe an end-to-end story; the synthetic generator
emits no events for unobservable phases.
"""
from __future__ import annotations

from enum import Enum


class UKCPhase(str, Enum):
    # In — initial foothold
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    SOCIAL_ENGINEERING = "social_engineering"
    EXPLOITATION = "exploitation"
    PERSISTENCE = "persistence"
    DEFENSE_EVASION = "defense_evasion"
    COMMAND_AND_CONTROL = "command_and_control"
    # Through — network propagation
    PIVOTING = "pivoting"
    DISCOVERY = "discovery"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    EXECUTION = "execution"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    # Out — action on objectives
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    OBJECTIVES = "objectives"


# Phases a honeypot can plausibly observe. Pre-target phases are excluded:
# OSINT recon, infrastructure-stand-up, payload authoring, and human-target
# manipulation all happen before the attacker touches a decky. The synthetic
# generator validates campaign specs against this set and warns (but does
# not error) on unobservable phases — a campaign can describe them; we just
# emit no events.
OBSERVABLE_PHASES: frozenset[UKCPhase] = frozenset({
    UKCPhase.DELIVERY,
    UKCPhase.EXPLOITATION,
    UKCPhase.PERSISTENCE,
    UKCPhase.DEFENSE_EVASION,
    UKCPhase.COMMAND_AND_CONTROL,
    UKCPhase.PIVOTING,
    UKCPhase.DISCOVERY,
    UKCPhase.PRIVILEGE_ESCALATION,
    UKCPhase.EXECUTION,
    UKCPhase.CREDENTIAL_ACCESS,
    UKCPhase.LATERAL_MOVEMENT,
    UKCPhase.COLLECTION,
    UKCPhase.EXFILTRATION,
    UKCPhase.IMPACT,
    UKCPhase.OBJECTIVES,
})


# Stage groupings — useful for the multi_operator fixture (operators tend
# to split along the In / Through / Out boundary) and for downstream
# UI rendering of campaign timelines.
STAGE_IN: frozenset[UKCPhase] = frozenset({
    UKCPhase.RECONNAISSANCE,
    UKCPhase.RESOURCE_DEVELOPMENT,
    UKCPhase.WEAPONIZATION,
    UKCPhase.DELIVERY,
    UKCPhase.SOCIAL_ENGINEERING,
    UKCPhase.EXPLOITATION,
    UKCPhase.PERSISTENCE,
    UKCPhase.DEFENSE_EVASION,
    UKCPhase.COMMAND_AND_CONTROL,
})

STAGE_THROUGH: frozenset[UKCPhase] = frozenset({
    UKCPhase.PIVOTING,
    UKCPhase.DISCOVERY,
    UKCPhase.PRIVILEGE_ESCALATION,
    UKCPhase.EXECUTION,
    UKCPhase.CREDENTIAL_ACCESS,
    UKCPhase.LATERAL_MOVEMENT,
})

STAGE_OUT: frozenset[UKCPhase] = frozenset({
    UKCPhase.COLLECTION,
    UKCPhase.EXFILTRATION,
    UKCPhase.IMPACT,
    UKCPhase.OBJECTIVES,
})


def stage_of(phase: UKCPhase) -> str:
    """Return 'in' | 'through' | 'out' for a given phase."""
    if phase in STAGE_IN:
        return "in"
    if phase in STAGE_THROUGH:
        return "through"
    return "out"
