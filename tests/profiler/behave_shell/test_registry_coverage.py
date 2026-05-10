"""Step H.1: registry-coverage test.

Static assertion that every Tier-A primitive in
``behave_shell.spec.primitives.PRIMITIVE_REGISTRY`` has a slot
in the calibration-grid binding sets — either the per-shard hard gate
(``PHASE_ABCDEFG_PRIMITIVES``) or one of the conditional sets
(``PHASE_D_CONDITIONAL_PRIMITIVES`` / ``PHASE_F_CONDITIONAL_PRIMITIVES``
/ ``PHASE_G_CONDITIONAL_PRIMITIVES``).

The test catches a future registry addition that DECNET hasn't
implemented yet — CI fails before the new primitive can ship without
a matching feature function.

Tier exclusion (mirrors ``BEHAVE-EXTRACTOR.md:180-223``):

* **Tier B — cross-session, attribution-engine territory:** computed
  by the attribution engine, never by the per-session extractor. The
  ``operational.multi_actor_indicators`` primitive is *Tier A* — only
  its ``team_coordinated`` value is cross-session, not the primitive
  itself.
* **Tier C — network domain:** every ``toolchain.*`` primitive is
  excluded by prefix. Sourced from sniffer / prober / correlation
  pipelines, not from PTY session extraction.
"""
from __future__ import annotations

from behave_shell.spec.primitives import PRIMITIVE_REGISTRY

from tests.profiler.behave_shell.test_calibration_grid import (
    PHASE_ABCDEFG_PRIMITIVES,
    PHASE_D_CONDITIONAL_PRIMITIVES,
    PHASE_F_CONDITIONAL_PRIMITIVES,
    PHASE_G_CONDITIONAL_PRIMITIVES,
)


# Tier B — cross-session primitives that the per-session extractor
# legitimately cannot honestly compute. The 8 primitives cited in
# ``BEHAVE-EXTRACTOR.md:189-198``.
TIER_B_ALLOWLIST: frozenset[str] = frozenset({
    "temporal.session_timing",
    "temporal.persistence",
    "temporal.lifecycle_markers.idle_periodicity",
    "cultural.meal_break_gaps",
    "cultural.periodic_micro_pauses",
    "cultural.dst_behavior",
    "cultural.weekend_cadence",
    "cultural.holiday_gaps",
})


def _tier_a_primitives() -> frozenset[str]:
    """Every primitive in the registry minus Tier B / Tier C."""
    return frozenset(
        p for p in PRIMITIVE_REGISTRY
        if not p.startswith("toolchain.") and p not in TIER_B_ALLOWLIST
    )


def _covered_primitives() -> frozenset[str]:
    return (
        PHASE_ABCDEFG_PRIMITIVES
        | PHASE_D_CONDITIONAL_PRIMITIVES
        | PHASE_F_CONDITIONAL_PRIMITIVES
        | PHASE_G_CONDITIONAL_PRIMITIVES
    )


def test_every_tier_a_primitive_has_a_feature_slot() -> None:
    """Hard gate: every Tier-A primitive must appear in the calibration
    grid's hard or conditional sets."""
    tier_a = _tier_a_primitives()
    covered = _covered_primitives()
    missing = tier_a - covered
    assert not missing, (
        "Tier-A primitives in registry but not covered by the "
        "calibration grid (likely a new spec entry without a "
        f"feature function): {sorted(missing)}"
    )


def test_no_extractor_set_drifts_from_registry() -> None:
    """Symmetric check: every name in the calibration grid must exist
    in the upstream registry. Catches typos and stale carry-overs."""
    covered = _covered_primitives()
    drift = covered - frozenset(PRIMITIVE_REGISTRY)
    assert not drift, (
        f"Calibration-grid names not in PRIMITIVE_REGISTRY (typos or "
        f"renamed in spec without grid update): {sorted(drift)}"
    )


def test_tier_a_count_is_37() -> None:
    """Sanity check: Tier-A count matches the design doc (37 primitives)."""
    assert len(_tier_a_primitives()) == 37, (
        f"Expected 37 Tier-A primitives per BEHAVE-EXTRACTOR.md; "
        f"got {len(_tier_a_primitives())}. Update Phase H if the "
        f"spec genuinely changed, or adjust TIER_B_ALLOWLIST."
    )
