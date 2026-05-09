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
from typing import Final


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


# MITRE ATT&CK tactic ID -> UKC phase. Covers the 14 enterprise tactics
# plus the four ICS tactics referenced by Appendix A.7 (Conpot, MQTT).
# Adding additional ICS tactics is a one-line addition. See
# TTP_TAGGING.md "UKC bridge".
ATTACK_TACTIC_TO_UKC: dict[str, UKCPhase] = {
    # Enterprise
    "TA0043": UKCPhase.RECONNAISSANCE,        # Reconnaissance
    "TA0042": UKCPhase.RESOURCE_DEVELOPMENT,  # Resource Development
    "TA0001": UKCPhase.DELIVERY,              # Initial Access
    "TA0002": UKCPhase.EXECUTION,             # Execution
    "TA0003": UKCPhase.PERSISTENCE,           # Persistence
    "TA0004": UKCPhase.PRIVILEGE_ESCALATION,  # Privilege Escalation
    "TA0005": UKCPhase.DEFENSE_EVASION,       # Defense Evasion
    "TA0006": UKCPhase.CREDENTIAL_ACCESS,     # Credential Access
    "TA0007": UKCPhase.DISCOVERY,             # Discovery
    "TA0008": UKCPhase.LATERAL_MOVEMENT,      # Lateral Movement
    "TA0009": UKCPhase.COLLECTION,            # Collection
    "TA0011": UKCPhase.COMMAND_AND_CONTROL,   # Command and Control
    "TA0010": UKCPhase.EXFILTRATION,          # Exfiltration
    "TA0040": UKCPhase.IMPACT,                # Impact
    # ICS — first-class projection so MQTT / Conpot / Modbus tags
    # don't drop out of campaign rollups when the clusterer projects
    # tactic to phase. ICS uses an independent tactic-ID range.
    "TA0100": UKCPhase.COLLECTION,            # ICS: Collection
    "TA0102": UKCPhase.DISCOVERY,             # ICS: Discovery
    "TA0105": UKCPhase.IMPACT,                # ICS: Impact
    "TA0106": UKCPhase.IMPACT,                # ICS: Impair Process Control
}


# ICS tactics live in a separate STIX bundle (mitre/ics-attack) that
# DECNET does not currently load. They're exempt from the
# enterprise-bundle validation in :func:`validate_against_attack_bundle`
# so a startup check doesn't false-fail the moment ICS rules are wired.
_NON_ENTERPRISE_TACTICS: Final[frozenset[str]] = frozenset(
    {"TA0100", "TA0102", "TA0105", "TA0106"}
)


def validate_against_attack_bundle() -> None:
    """Assert every enterprise tactic ID in :data:`ATTACK_TACTIC_TO_UKC` resolves in the loaded STIX bundle.

    Called at startup (see :mod:`decnet.ttp.impl.rule_engine`) so a
    typoed tactic ID surfaces as a fail-closed boot, not a silent
    miss in campaign rollups.
    """
    from decnet.ttp.attack_stix import assert_known_tactic_ids

    assert_known_tactic_ids(
        list(ATTACK_TACTIC_TO_UKC.keys()),
        source="decnet.clustering.ukc.ATTACK_TACTIC_TO_UKC",
        exempt=set(_NON_ENTERPRISE_TACTICS),
    )


def tactic_to_ukc_phase(tactic: str) -> UKCPhase | None:
    """Map an ATT&CK tactic ID (e.g. ``"TA0001"``) to a :class:`UKCPhase`.

    Returns ``None`` for unknown tactics. The map is closed-over the
    enterprise + ICS tactics referenced by the rule pack; a tactic
    outside that set is a contributor bug, not a runtime miss.
    """
    return ATTACK_TACTIC_TO_UKC.get(tactic)


# Inverse map, built once at import time. Several enterprise tactics
# would collide (e.g. both TA0009 and TA0100 map to COLLECTION); the
# enterprise tactic wins because it's listed first in
# ATTACK_TACTIC_TO_UKC, which dict comprehension preserves via
# last-write semantics — so we iterate in reverse to keep the FIRST
# occurrence per phase. Pre-target phases (RECONNAISSANCE,
# RESOURCE_DEVELOPMENT, WEAPONIZATION, SOCIAL_ENGINEERING) that are
# not in OBSERVABLE_PHASES are deliberately lossy on the inverse —
# TTP tags must never assign them, so projecting back to a tactic
# is undefined. See TTP_TAGGING.md §UKC bridge.
_UKC_TO_TACTIC: dict[UKCPhase, str] = {
    phase: tactic
    for tactic, phase in reversed(list(ATTACK_TACTIC_TO_UKC.items()))
}


def ukc_phase_to_tactic(phase: UKCPhase) -> str | None:
    """Map a :class:`UKCPhase` back to an ATT&CK tactic ID.

    Lossy on phases outside :data:`OBSERVABLE_PHASES` — pre-target
    phases (e.g. ``RECONNAISSANCE``, ``WEAPONIZATION``) return
    ``None`` because no rule emits them, so the inverse is
    undefined by design. The CDD test in E.2.9 pins which phases
    are lossy.
    """
    return _UKC_TO_TACTIC.get(phase)
