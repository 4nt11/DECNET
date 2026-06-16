# SPDX-License-Identifier: AGPL-3.0-or-later
"""Campaign-level keystroke-rhythm edge.

The digraph-SimHash centroid is a *supporting* signal: a typing match
alone must not merge two identities (FP guard), but it tips an otherwise
sub-threshold pair (e.g. co-temporal identities) into one campaign.
"""
from __future__ import annotations

from decnet.clustering.campaign.impl.connected_components import from_identity_row
from decnet.clustering.campaign.impl.similarity import (
    CAMPAIGN_EDGE_THRESHOLD,
    KD_HAMMING_MAX,
    IdentityFeatures,
    combined_campaign_weight,
    keystroke_weight,
)
from decnet.util.simhash import to_bytes8

_H = 0xABCD1234ABCD1234


def _flip_low_bits(value: int, n: int) -> int:
    """XOR the n low bits → a hash exactly n bits away from ``value``."""
    return value ^ ((1 << n) - 1)


def test_identical_rhythm_is_full_weight() -> None:
    a = IdentityFeatures("a", kd_digraph_simhash=_H)
    b = IdentityFeatures("b", kd_digraph_simhash=_H)
    assert keystroke_weight(a, b) == 1.0


def test_missing_centroid_is_zero() -> None:
    a = IdentityFeatures("a", kd_digraph_simhash=_H)
    b = IdentityFeatures("b")  # no biometric yet
    assert keystroke_weight(a, b) == 0.0


def test_weight_grades_by_hamming() -> None:
    half = KD_HAMMING_MAX // 2
    a = IdentityFeatures("a", kd_digraph_simhash=_H)
    b = IdentityFeatures("b", kd_digraph_simhash=_flip_low_bits(_H, half))
    assert keystroke_weight(a, b) == 1.0 - half / KD_HAMMING_MAX


def test_far_apart_contributes_nothing() -> None:
    a = IdentityFeatures("a", kd_digraph_simhash=_H)
    b = IdentityFeatures("b", kd_digraph_simhash=_flip_low_bits(_H, KD_HAMMING_MAX))
    assert keystroke_weight(a, b) == 0.0


def test_typing_alone_does_not_merge() -> None:
    # FP guard: identical rhythm, no other signal → below threshold.
    a = IdentityFeatures("a", kd_digraph_simhash=_H)
    b = IdentityFeatures("b", kd_digraph_simhash=_H)
    assert combined_campaign_weight(a, b) < CAMPAIGN_EDGE_THRESHOLD


def test_typing_plus_temporal_overlap_crosses_threshold() -> None:
    window = ((0.0, 100.0),)
    a = IdentityFeatures("a", kd_digraph_simhash=_H, session_windows=window)
    b = IdentityFeatures("b", kd_digraph_simhash=_H, session_windows=window)
    # temporal overlap (0.4) + keystroke (0.6) reaches the 1.0 threshold.
    assert combined_campaign_weight(a, b) >= CAMPAIGN_EDGE_THRESHOLD
    # Strip the biometric and the same co-temporal pair falls back under.
    a2 = IdentityFeatures("a", session_windows=window)
    b2 = IdentityFeatures("b", session_windows=window)
    assert combined_campaign_weight(a2, b2) < CAMPAIGN_EDGE_THRESHOLD


def test_from_identity_row_projects_bytes_and_none() -> None:
    feat = from_identity_row({"uuid": "x", "kd_digraph_simhash": to_bytes8(_H)})
    assert feat.kd_digraph_simhash == _H
    assert from_identity_row({"uuid": "y"}).kd_digraph_simhash is None
