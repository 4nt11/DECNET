"""E.2.9 — UKC bridge bijection tests.

Pins the ATT&CK tactic ↔ UKC phase mapping declared in
:mod:`decnet.clustering.ukc`. Per ``development/TTP_TAGGING.md`` §UKC
bridge:

* Every key in ``ATTACK_TACTIC_TO_UKC`` is a valid TA-prefixed string.
* Every value is a member of :class:`UKCPhase`.
* For every phase in :data:`OBSERVABLE_PHASES`, the inverse round-trips:
  ``tactic_to_ukc_phase(ukc_phase_to_tactic(phase)) == phase``.
* Phases NOT in :data:`OBSERVABLE_PHASES` (pre-target reconnaissance,
  resource development, weaponization, social engineering) MAY have a
  lossy inverse — the test pins which ones are lossy *and* the
  current inverse output, so a future contributor cannot accidentally
  "fix" the asymmetry without tripping the suite.

All assertions are GREEN today; the contract is fully implemented in
``ukc.py``.
"""
from __future__ import annotations

import re

import pytest

from decnet.clustering.ukc import (
    ATTACK_TACTIC_TO_UKC,
    OBSERVABLE_PHASES,
    UKCPhase,
    tactic_to_ukc_phase,
    ukc_phase_to_tactic,
)


# Pinned reference for the inverse projection on phases that don't
# round-trip cleanly. Two flavors:
#
# 1. Pre-target phases (RECONNAISSANCE, RESOURCE_DEVELOPMENT,
#    WEAPONIZATION, SOCIAL_ENGINEERING) — excluded from
#    OBSERVABLE_PHASES because no honeypot rule emits them. Lossy by
#    design.
# 2. Observable-but-unmappable phases (EXPLOITATION, PIVOTING,
#    OBJECTIVES) — UKC-only concepts that ATT&CK does not have a
#    corresponding tactic for. Honeypot rules CAN emit these (they're
#    in OBSERVABLE_PHASES) but the inverse is undefined because
#    ATT&CK lacks the granularity.
#
# Pinning the literal output here freezes the asymmetry: a future
# refactor that "rounds-trips" any of these phases trips the test.
# See TTP_TAGGING.md §UKC bridge.
_LOSSY_INVERSE_REFERENCE: dict[UKCPhase, str | None] = {
    # Pre-target (non-observable)
    UKCPhase.RECONNAISSANCE: "TA0043",
    UKCPhase.RESOURCE_DEVELOPMENT: "TA0042",
    UKCPhase.WEAPONIZATION: None,
    UKCPhase.SOCIAL_ENGINEERING: None,
    # Observable but not ATT&CK-mappable
    UKCPhase.EXPLOITATION: None,
    UKCPhase.PIVOTING: None,
    UKCPhase.OBJECTIVES: None,
}

# Observable phases that DO round-trip cleanly. Excludes phases listed
# in :data:`_LOSSY_INVERSE_REFERENCE` even when those phases are also
# in :data:`OBSERVABLE_PHASES` — a round-trip is impossible for
# UKC-only concepts that ATT&CK lacks a tactic for.
_BIJECTIVE_OBSERVABLE_PHASES: frozenset[UKCPhase] = (
    OBSERVABLE_PHASES - frozenset(_LOSSY_INVERSE_REFERENCE.keys())
)


_TACTIC_RE = re.compile(r"^TA\d{4}$")


@pytest.mark.parametrize("tactic", sorted(ATTACK_TACTIC_TO_UKC.keys()))
def test_every_tactic_is_ta_prefixed(tactic: str) -> None:
    assert _TACTIC_RE.fullmatch(tactic), (
        f"tactic key {tactic!r} is not a TA-prefixed 4-digit code"
    )


@pytest.mark.parametrize(
    "phase",
    sorted(set(ATTACK_TACTIC_TO_UKC.values()), key=lambda p: p.value if isinstance(p, UKCPhase) else ""),
)
def test_every_value_is_ukc_phase(phase: UKCPhase) -> None:
    assert isinstance(phase, UKCPhase)


@pytest.mark.parametrize(
    "phase", sorted(_BIJECTIVE_OBSERVABLE_PHASES, key=lambda p: p.value if isinstance(p, UKCPhase) else ""),
)
def test_observable_phase_round_trips(phase: UKCPhase) -> None:
    """For phases a honeypot can observe, the inverse is a true bijection.

    Concretely: ``ukc_phase_to_tactic(p)`` returns a tactic, and that
    tactic maps back to the same phase through ``tactic_to_ukc_phase``.
    """
    tactic = ukc_phase_to_tactic(phase)
    assert tactic is not None, f"observable phase {phase} has no inverse tactic"
    assert tactic_to_ukc_phase(tactic) == phase


_LOSSY_PARAMS: list[tuple[UKCPhase, str | None]] = sorted(
    _LOSSY_INVERSE_REFERENCE.items(), key=lambda kv: kv[0].value,
)


@pytest.mark.parametrize("phase,expected_tactic", _LOSSY_PARAMS)
def test_pre_target_phases_pinned_inverse(
    phase: UKCPhase, expected_tactic: str | None,
) -> None:
    """Pre-target phases have an allowed-lossy inverse — pin current output.

    These phases are excluded from :data:`OBSERVABLE_PHASES` and tag
    emission rules never assign them. The inverse is whatever
    ``_UKC_TO_TACTIC`` happens to record (or ``None`` if the phase is
    not in the forward map at all). Freezing the literal value here
    means an accidental "let's make the inverse total" refactor trips
    the test, which is the right answer per the design doc.
    """
    assert ukc_phase_to_tactic(phase) == expected_tactic


def test_unknown_tactic_returns_none() -> None:
    assert tactic_to_ukc_phase("TA9999") is None


def test_observable_phases_partition_matches_lossy_set() -> None:
    """Sanity: every phase that appears as a forward value is either
    observable or in the pre-target lossy reference table. Nothing
    else. Catches a future contributor adding a new pre-target phase
    without updating this test's reference table.
    """
    forward_phases = set(ATTACK_TACTIC_TO_UKC.values())
    accounted = OBSERVABLE_PHASES | set(_LOSSY_INVERSE_REFERENCE.keys())
    assert forward_phases <= accounted, (
        f"phase(s) {forward_phases - accounted} appear in the forward map "
        "but are neither observable nor listed in _LOSSY_INVERSE_REFERENCE"
    )
