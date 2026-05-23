# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sanity tests for the clustering metric harness."""
from __future__ import annotations

import pytest

from tests.clustering.metrics import (
    adjusted_rand_index,
    completeness,
    homogeneity,
    score,
    singleton_recall,
)


def test_perfect_agreement_scores_one() -> None:
    truth = {"a": "C1", "b": "C1", "c": "C2", "d": "C2"}
    # Same partition, different label names — clustering doesn't preserve
    # names, so renamed-but-isomorphic must still score 1.0.
    pred = {"a": "X", "b": "X", "c": "Y", "d": "Y"}
    s = score(truth, pred)
    assert s["adjusted_rand_index"] == pytest.approx(1.0)
    assert s["homogeneity"] == pytest.approx(1.0)
    assert s["completeness"] == pytest.approx(1.0)
    assert s["singleton_recall"] == pytest.approx(1.0)


def test_all_singletons_perfect() -> None:
    truth = {"a": "A", "b": "B", "c": "C"}
    pred = {"a": "1", "b": "2", "c": "3"}
    s = score(truth, pred)
    assert s["singleton_recall"] == pytest.approx(1.0)
    assert s["adjusted_rand_index"] == pytest.approx(1.0)


def test_false_merge_drops_homogeneity() -> None:
    truth = {"a": "C1", "b": "C2"}
    pred = {"a": "X", "b": "X"}  # merged two distinct campaigns
    assert homogeneity(truth, pred) == pytest.approx(0.0)
    # Completeness is fine (each true class lives in one cluster).
    assert completeness(truth, pred) == pytest.approx(1.0)


def test_false_split_drops_completeness() -> None:
    truth = {"a": "C1", "b": "C1"}
    pred = {"a": "X", "b": "Y"}  # split one campaign into two clusters
    assert completeness(truth, pred) == pytest.approx(0.0)
    assert homogeneity(truth, pred) == pytest.approx(1.0)


def test_singleton_recall_penalises_noise_absorption() -> None:
    # 3 lone wolves + 1 real campaign with 2 members.
    truth = {"w1": "wolf1", "w2": "wolf2", "w3": "wolf3", "c1": "C", "c2": "C"}
    # Clusterer absorbs all wolves into the campaign.
    pred = dict.fromkeys(truth, "BIG")
    assert singleton_recall(truth, pred) == pytest.approx(0.0)
    # And a clusterer that keeps wolves singleton should score 1.0
    # on this metric, regardless of what it does with the campaign.
    pred_ok = {"w1": "1", "w2": "2", "w3": "3", "c1": "C", "c2": "C"}
    assert singleton_recall(truth, pred_ok) == pytest.approx(1.0)


def test_mismatched_item_sets_raises() -> None:
    with pytest.raises(ValueError):
        adjusted_rand_index({"a": "X"}, {"b": "Y"})


def test_random_labels_low_ari() -> None:
    # ARI of an arbitrary partition vs. ground truth should be near 0,
    # not near 1 — this is the chance-correction guarantee.
    truth = {f"i{n}": f"C{n // 4}" for n in range(20)}
    # Pred that ignores truth: just shuffles items into 5 buckets in
    # an order uncorrelated with truth.
    pred = {f"i{n}": f"X{(n * 7) % 5}" for n in range(20)}
    ari = adjusted_rand_index(truth, pred)
    # Loose bound — the point is "much closer to 0 than to 1".
    assert ari < 0.3
