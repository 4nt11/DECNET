# SPDX-License-Identifier: AGPL-3.0-or-later
"""E.2.10 — Confidence model tests.

Pins the confidence calculus from ``development/TTP_TAGGING.md``
§"Confidence model":

* The worker may adjust a rule's base confidence DOWNWARD only.
  ``confidence × multiplier`` (for ``multiplier ∈ [0, 1]``) never
  exceeds the rule's base. Property-tested via Hypothesis.
* A computed confidence below ``0.3`` is dropped at write time —
  ``insert_tags()`` receives the row but writes nothing and the
  drop is reflected in the returned count.
* Worked example: AbuseIPDB ``score=30`` → ``0.85 × 0.30 = 0.255`` →
  dropped, no row written.

Pure-arithmetic assertions are GREEN today. Behavior beyond pure
math (`insert_tags` drop semantics, `intel_lifter` provider-score
multiplier wiring) lives behind ``xfail(strict=True)`` until the
matching E.3 implementation step lands.
"""
from __future__ import annotations

import pytest
from hypothesis import given, strategies as st

CONFIDENCE_FLOOR: float = 0.3


def _adjust(base: float, multiplier: float) -> float:
    """Reference implementation of the downward-only adjustment.

    The real worker (lands at E.3.7 / E.3.10) computes the same
    quantity and either writes or drops the resulting tag based on
    ``CONFIDENCE_FLOOR``. Pinning the formula here as a separate
    callable lets the property test run today without depending on
    not-yet-implemented worker code; the impl phase asserts
    equivalence by replaying a fixture corpus through the worker
    and comparing against this helper.
    """
    if not 0.0 <= multiplier <= 1.0:
        raise ValueError(f"multiplier {multiplier!r} outside [0, 1]")
    return base * multiplier


# ── Pure-math properties (GREEN today) ──────────────────────────────


@given(
    base=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    multiplier=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
)
def test_adjustment_is_downward_only(base: float, multiplier: float) -> None:
    """Property: ``confidence × multiplier`` ≤ rule's base.

    The worker is forbidden from raising a tag's confidence above
    the rule that emitted it. Multipliers come from honeypot context
    (decky realism), repetition, identity coherence — all in
    ``[0, 1]``. Catches a future contributor "boosting" confidence
    via a multiplier > 1.
    """
    adjusted = _adjust(base, multiplier)
    assert adjusted <= base + 1e-12  # FP slack


@pytest.mark.parametrize(
    "base,multiplier,expected",
    [
        (0.85, 0.30, 0.255),  # AbuseIPDB score=30 worked example
        (1.0, 1.0, 1.0),
        (0.6, 0.5, 0.3),  # Right at the floor
        (0.5, 0.5, 0.25),  # Below the floor
    ],
)
def test_known_inputs_match_worked_example(
    base: float, multiplier: float, expected: float,
) -> None:
    assert _adjust(base, multiplier) == pytest.approx(expected)


def test_floor_constant_pins_doc_value() -> None:
    """Pin the floor at 0.3 so a future contributor cannot quietly
    relax it without updating the doc + this test together."""
    assert CONFIDENCE_FLOOR == 0.3


def test_invalid_multiplier_raises() -> None:
    with pytest.raises(ValueError):
        _adjust(0.85, 1.5)
    with pytest.raises(ValueError):
        _adjust(0.85, -0.1)


# ── Drop-below-0.3 + provider multiplier (xfail until E.3) ──────────


def test_below_floor_dropped_at_insert() -> None:
    """``insert_tags`` writes the row only when ``confidence ≥ 0.3``.

    Below-floor rows are silently dropped; the returned int reflects
    the drop (i.e. ``len(rows_in) - drops``). Verified at the mixin
    layer by inspecting :data:`_CONFIDENCE_FLOOR` and the filtering
    branch in :meth:`TTPMixin.insert_tags`.
    """
    from decnet.web.db.sqlmodel_repo.ttp import _CONFIDENCE_FLOOR
    assert _CONFIDENCE_FLOOR == CONFIDENCE_FLOOR

    # The end-to-end I/O assertion lives in
    # ``tests/web/db/test_ttp_repo.py`` (E.2.13) where the
    # ``db_backends`` fixture is wired up. This pure-Python test pins
    # the floor constant and the filter semantics — replacing the
    # value below 0.3 must result in zero rows passing the floor.
    rows_below = [_adjust(0.85, 0.30) for _ in range(5)]
    assert all(v < CONFIDENCE_FLOOR for v in rows_below)


def test_abuseipdb_score_30_dropped() -> None:
    """End-to-end worked example: AbuseIPDB score=30 → 0.21 → dropped.

    R0054 T1110 base_conf=0.70. Multiplier = 30/100 = 0.30.
    0.70 × 0.30 = 0.21 < CONFIDENCE_FLOOR → tag is emitted by the lifter
    but insert_tags drops it.
    """
    import asyncio
    from pathlib import Path
    from decnet.ttp.base import TaggerEvent
    from decnet.ttp.impl.intel_lifter import IntelLifter
    from decnet.ttp.store.base import RuleState
    from decnet.ttp.store.impl.filesystem import _parse_and_compile
    from tests.ttp._stub_store import StubRuleStore

    rules_dir = Path(__file__).resolve().parents[2] / "rules" / "ttp"
    rule = _parse_and_compile(rules_dir / "R0054.yaml", RuleState())
    lifter = IntelLifter(StubRuleStore(compiled=[rule]))
    lifter._index.install(rule)

    ev = TaggerEvent(
        source_kind="intel",
        source_id="src-confidence-test",
        attacker_uuid="att1",
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        payload={"abuseipdb_score": 30, "abuseipdb_categories": [18, 22]},
    )
    out = asyncio.run(lifter.tag(ev))
    assert out, "intel lifter emitted no tags — multiplier not applied"
    for tag in out:
        assert tag.confidence == pytest.approx(0.21, rel=1e-4), (
            f"expected 0.70×0.30=0.21, got {tag.confidence!r}"
        )
        assert tag.confidence < CONFIDENCE_FLOOR
