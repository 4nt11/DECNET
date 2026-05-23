# SPDX-License-Identifier: AGPL-3.0-or-later
"""Tests for campaign-level similarity primitives.

Covers, in order:

* Each edge family in isolation — phase-handoff, shared-infra,
  temporal-overlap, cohort.
* The F7 (slow_burn) time-agnostic invariant — shifting every
  timestamp on both sides by the same Δ preserves every edge weight.
* The F1 (shared_wordlist) failure mode — shared cohort alone must
  NOT push a pair over threshold.
* The F5 (multi_operator) target — phase-handoff alone (the
  load-bearing campaign-level signal) DOES cross threshold.
* Tier-combination arithmetic — shared-infra + temporal overlap
  (the canonical co-op pattern) crosses threshold; shared-infra +
  cohort does not.
"""
from __future__ import annotations

import pytest

from decnet.clustering.campaign.impl.similarity import (
    CAMPAIGN_EDGE_THRESHOLD,
    DEFAULT_HANDOFF_WINDOW_S,
    IdentityFeatures,
    cohort_weight,
    combined_campaign_weight,
    phase_handoff_weight,
    shared_infra_weight,
    temporal_overlap_weight,
)


def _features(uuid: str, **kwargs) -> IdentityFeatures:
    return IdentityFeatures(identity_uuid=uuid, **kwargs)


# ─── phase_handoff_weight ────────────────────────────────────────────────────


def test_phase_handoff_clean_out_to_in_within_window():
    a = _features(
        "a",
        last_phase_per_decky={"d1": "command_and_control"},
        last_seen_per_decky={"d1": 1000.0},
    )
    b = _features(
        "b",
        first_phase_per_decky={"d1": "discovery"},
        first_seen_per_decky={"d1": 1000.0 + 600.0},  # 10 min later
    )
    assert phase_handoff_weight(a, b) == 1.0


def test_phase_handoff_symmetric():
    # B finishes, A picks up. The argument order shouldn't matter.
    b = _features(
        "b",
        last_phase_per_decky={"d1": "persistence"},
        last_seen_per_decky={"d1": 5000.0},
    )
    a = _features(
        "a",
        first_phase_per_decky={"d1": "lateral_movement"},
        first_seen_per_decky={"d1": 5000.0 + 60.0},
    )
    assert phase_handoff_weight(a, b) == 1.0
    assert phase_handoff_weight(b, a) == 1.0


def test_phase_handoff_no_decky_overlap():
    a = _features(
        "a",
        last_phase_per_decky={"d1": "command_and_control"},
        last_seen_per_decky={"d1": 1000.0},
    )
    b = _features(
        "b",
        first_phase_per_decky={"d2": "discovery"},
        first_seen_per_decky={"d2": 1100.0},
    )
    assert phase_handoff_weight(a, b) == 0.0


def test_phase_handoff_phase_mismatch():
    # A ends mid-pivoting (not a handoff-out phase) → no signal.
    a = _features(
        "a",
        last_phase_per_decky={"d1": "exploitation"},
        last_seen_per_decky={"d1": 1000.0},
    )
    b = _features(
        "b",
        first_phase_per_decky={"d1": "discovery"},
        first_seen_per_decky={"d1": 1100.0},
    )
    assert phase_handoff_weight(a, b) == 0.0


def test_phase_handoff_outside_window():
    a = _features(
        "a",
        last_phase_per_decky={"d1": "command_and_control"},
        last_seen_per_decky={"d1": 0.0},
    )
    b = _features(
        "b",
        first_phase_per_decky={"d1": "discovery"},
        # Way past the 24h default window.
        first_seen_per_decky={"d1": DEFAULT_HANDOFF_WINDOW_S + 3600.0},
    )
    assert phase_handoff_weight(a, b) == 0.0


def test_phase_handoff_negative_gap_rejected():
    # B starts BEFORE A ends — that's overlap, not a handoff.
    a = _features(
        "a",
        last_phase_per_decky={"d1": "persistence"},
        last_seen_per_decky={"d1": 2000.0},
    )
    b = _features(
        "b",
        first_phase_per_decky={"d1": "lateral_movement"},
        first_seen_per_decky={"d1": 1000.0},
    )
    assert phase_handoff_weight(a, b) == 0.0


# ─── shared_infra_weight ─────────────────────────────────────────────────────


def test_shared_infra_full_overlap():
    a = _features(
        "a",
        payload_hashes=frozenset({"hash-1"}),
        c2_endpoints=frozenset({"1.2.3.4:443"}),
        decky_set=frozenset({"d1"}),
    )
    b = _features(
        "b",
        payload_hashes=frozenset({"hash-1"}),
        c2_endpoints=frozenset({"1.2.3.4:443"}),
        decky_set=frozenset({"d1"}),
    )
    assert shared_infra_weight(a, b) == 1.0


def test_shared_infra_no_overlap():
    a = _features("a", payload_hashes=frozenset({"hash-a"}))
    b = _features("b", payload_hashes=frozenset({"hash-b"}))
    assert shared_infra_weight(a, b) == 0.0


def test_shared_infra_empty_returns_zero():
    a = _features("a")
    b = _features("b")
    assert shared_infra_weight(a, b) == 0.0


# ─── temporal_overlap_weight ─────────────────────────────────────────────────


def test_temporal_overlap_full():
    a = _features("a", session_windows=((0.0, 100.0),))
    b = _features("b", session_windows=((0.0, 100.0),))
    assert temporal_overlap_weight(a, b) == 1.0


def test_temporal_overlap_partial():
    a = _features("a", session_windows=((0.0, 100.0),))
    b = _features("b", session_windows=((50.0, 150.0),))
    # 50 of 100 of A's time overlaps B.
    assert temporal_overlap_weight(a, b) == pytest.approx(0.5)


def test_temporal_overlap_disjoint():
    a = _features("a", session_windows=((0.0, 100.0),))
    b = _features("b", session_windows=((200.0, 300.0),))
    assert temporal_overlap_weight(a, b) == 0.0


def test_temporal_overlap_empty():
    a = _features("a")
    b = _features("b", session_windows=((0.0, 100.0),))
    assert temporal_overlap_weight(a, b) == 0.0


# ─── cohort_weight ───────────────────────────────────────────────────────────


def test_cohort_asn_overlap():
    a = _features("a", asn_cohort=frozenset({64512}))
    b = _features("b", asn_cohort=frozenset({64512}))
    assert cohort_weight(a, b) == 1.0


def test_cohort_disjoint():
    a = _features("a", asn_cohort=frozenset({64512}))
    b = _features("b", asn_cohort=frozenset({64513}))
    assert cohort_weight(a, b) == 0.0


# ─── F7 time-agnostic invariant ──────────────────────────────────────────────


def test_f7_invariant_temporal_overlap_unchanged_under_shift():
    # The fixture-7 (slow_burn) invariant: shifting every timestamp on
    # BOTH sides by the same Δ must yield the same edge weight. The
    # campaign clusterer's edges are pairwise-relative; an absolute
    # 90-day shift must not change anything.
    a = _features("a", session_windows=((0.0, 100.0), (300.0, 400.0)))
    b = _features("b", session_windows=((50.0, 150.0), (350.0, 450.0)))
    base = temporal_overlap_weight(a, b)
    shift = 90 * 24 * 3600.0
    a_shifted = _features(
        "a",
        session_windows=tuple((s + shift, e + shift) for s, e in a.session_windows),
    )
    b_shifted = _features(
        "b",
        session_windows=tuple((s + shift, e + shift) for s, e in b.session_windows),
    )
    assert temporal_overlap_weight(a_shifted, b_shifted) == pytest.approx(base)


def test_f7_invariant_phase_handoff_unchanged_under_shift():
    a = _features(
        "a",
        last_phase_per_decky={"d1": "command_and_control"},
        last_seen_per_decky={"d1": 1000.0},
    )
    b = _features(
        "b",
        first_phase_per_decky={"d1": "discovery"},
        first_seen_per_decky={"d1": 1600.0},
    )
    base = phase_handoff_weight(a, b)

    shift = 90 * 24 * 3600.0
    a_shifted = _features(
        "a",
        last_phase_per_decky=dict(a.last_phase_per_decky),
        last_seen_per_decky={k: v + shift for k, v in a.last_seen_per_decky.items()},
    )
    b_shifted = _features(
        "b",
        first_phase_per_decky=dict(b.first_phase_per_decky),
        first_seen_per_decky={k: v + shift for k, v in b.first_seen_per_decky.items()},
    )
    assert phase_handoff_weight(a_shifted, b_shifted) == base == 1.0


# ─── Combined-weight + threshold semantics ──────────────────────────────────


def test_phase_handoff_alone_crosses_threshold():
    """F5 multi_operator's load-bearing signal: handoff alone is enough."""
    a = _features(
        "a",
        last_phase_per_decky={"d1": "persistence"},
        last_seen_per_decky={"d1": 1000.0},
    )
    b = _features(
        "b",
        first_phase_per_decky={"d1": "lateral_movement"},
        first_seen_per_decky={"d1": 1100.0},
    )
    assert combined_campaign_weight(a, b) >= CAMPAIGN_EDGE_THRESHOLD


def test_cohort_alone_below_threshold():
    """F2 vpn_hopping at campaign level: cohort alone is not co-op."""
    a = _features("a", asn_cohort=frozenset({64512}))
    b = _features("b", asn_cohort=frozenset({64512}))
    assert combined_campaign_weight(a, b) < CAMPAIGN_EDGE_THRESHOLD


def test_shared_infra_alone_crosses_threshold():
    """Shared payload + C2 alone is enough — F5's intended pass condition."""
    a = _features(
        "a",
        payload_hashes=frozenset({"h"}),
        c2_endpoints=frozenset({"c"}),
    )
    b = _features(
        "b",
        payload_hashes=frozenset({"h"}),
        c2_endpoints=frozenset({"c"}),
    )
    assert combined_campaign_weight(a, b) >= CAMPAIGN_EDGE_THRESHOLD


def test_decky_overlap_alone_below_threshold():
    """F1's failure mode: shared targeting on a small fleet is NOT co-op.

    Two campaigns hitting the same SSH deckies share no payload/C2,
    just the decky set. Cohort tier alone must not cross threshold.
    """
    a = _features(
        "a",
        decky_set=frozenset({"d1", "d2"}),
        asn_cohort=frozenset({64512}),
    )
    b = _features(
        "b",
        decky_set=frozenset({"d1", "d2"}),
        asn_cohort=frozenset({64513}),
    )
    assert combined_campaign_weight(a, b) < CAMPAIGN_EDGE_THRESHOLD


def test_combined_invariant_under_shift():
    """End-to-end F7 invariant on the combined weight."""
    a = _features(
        "a",
        last_phase_per_decky={"d1": "persistence"},
        last_seen_per_decky={"d1": 1000.0},
        session_windows=((0.0, 1500.0),),
        payload_hashes=frozenset({"h"}),
    )
    b = _features(
        "b",
        first_phase_per_decky={"d1": "discovery"},
        first_seen_per_decky={"d1": 1100.0},
        session_windows=((1100.0, 2000.0),),
        payload_hashes=frozenset({"h"}),
    )
    base = combined_campaign_weight(a, b)
    shift = 90 * 24 * 3600.0
    a_shifted = IdentityFeatures(
        identity_uuid=a.identity_uuid,
        last_phase_per_decky=dict(a.last_phase_per_decky),
        last_seen_per_decky={k: v + shift for k, v in a.last_seen_per_decky.items()},
        session_windows=tuple((s + shift, e + shift) for s, e in a.session_windows),
        payload_hashes=a.payload_hashes,
    )
    b_shifted = IdentityFeatures(
        identity_uuid=b.identity_uuid,
        first_phase_per_decky=dict(b.first_phase_per_decky),
        first_seen_per_decky={k: v + shift for k, v in b.first_seen_per_decky.items()},
        session_windows=tuple((s + shift, e + shift) for s, e in b.session_windows),
        payload_hashes=b.payload_hashes,
    )
    assert combined_campaign_weight(a_shifted, b_shifted) == pytest.approx(base)
