# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Clustering metric harness — see development/CAMPAIGN_CLUSTERING.md §3.

Decided BEFORE any clustering algorithm exists, on purpose: if the
metrics get picked after seeing results, they'll flatter whatever the
algorithm happens to produce.

Four metrics, none on its own sufficient:

  * Adjusted Rand Index — headline number, chance-corrected agreement
    between predicted clusters and ground truth.
  * Homogeneity — each predicted cluster contains only one true class.
    Catches FALSE MERGES (campaigns wrongly fused).
  * Completeness — every member of a true class lands in the same
    predicted cluster. Catches FALSE SPLITS (one campaign wrongly torn
    apart).
  * Singleton recall — fraction of ground-truth singletons (lone wolves,
    background noise) that are kept singleton by the clusterer.

Implemented from first principles in pure Python so the test harness
doesn't pull sklearn/numpy into the runtime dependency surface.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict


def _comb2(n: int) -> int:
    """C(n, 2) — number of unordered pairs from n items."""
    return n * (n - 1) // 2 if n >= 2 else 0


def adjusted_rand_index(truth: dict[str, str], pred: dict[str, str]) -> float:
    """
    Adjusted Rand Index between two clusterings over the same item set.

    Range: typically [0, 1]; can dip negative for worse-than-random
    labelings. 1.0 = identical partitions (up to label renaming),
    0.0 ≈ chance agreement.

    Both args map item_id -> cluster_id. Items must align exactly.
    """
    if set(truth) != set(pred):
        raise ValueError(
            "ARI requires identical item sets in truth and pred "
            f"(missing in pred: {set(truth) - set(pred)}, "
            f"missing in truth: {set(pred) - set(truth)})"
        )
    n = len(truth)
    if n < 2:
        return 1.0  # trivially "agree" on <2 items

    # Build the contingency table n_ij = |cluster_i ∩ class_j|.
    contingency: dict[tuple[str, str], int] = defaultdict(int)
    for item, t_label in truth.items():
        p_label = pred[item]
        contingency[(p_label, t_label)] += 1

    sum_comb = sum(_comb2(v) for v in contingency.values())
    a_counts = Counter(pred.values())   # row sums (predicted clusters)
    b_counts = Counter(truth.values())  # column sums (true classes)
    sum_a = sum(_comb2(v) for v in a_counts.values())
    sum_b = sum(_comb2(v) for v in b_counts.values())
    total_pairs = _comb2(n)

    expected = (sum_a * sum_b) / total_pairs if total_pairs else 0.0
    max_index = (sum_a + sum_b) / 2
    if max_index == expected:
        # Degenerate: both clusterings are trivially equal in structure
        # (both all-singletons, or both one-big-cluster). The math forces
        # this — see the algebra of max_index = expected. The induced
        # partitions are necessarily identical, so ARI is 1.0. (sklearn
        # adopts the same convention.)
        return 1.0
    return (sum_comb - expected) / (max_index - expected)


def _entropy(counts: list[int], total: int) -> float:
    if total == 0:
        return 0.0
    h = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        h -= p * math.log(p)
    return h


def _conditional_entropy(
    contingency: dict[tuple[str, str], int],
    given_counts: dict[str, int],
    total: int,
) -> float:
    """H(rows | cols) — i.e. entropy of class within each cluster."""
    if total == 0:
        return 0.0
    h = 0.0
    by_col: dict[str, list[int]] = defaultdict(list)
    for (row, col), v in contingency.items():
        by_col[col].append(v)
    for col, vs in by_col.items():
        col_total = given_counts[col]
        if col_total == 0:
            continue
        col_entropy = _entropy(vs, col_total)
        h += (col_total / total) * col_entropy
    return h


def homogeneity(truth: dict[str, str], pred: dict[str, str]) -> float:
    """
    1 - H(truth | pred) / H(truth). 1.0 = each predicted cluster
    contains only members of a single true class (no false merges).
    """
    n = len(truth)
    if n == 0:
        return 1.0
    contingency: dict[tuple[str, str], int] = defaultdict(int)
    for item, t in truth.items():
        contingency[(t, pred[item])] += 1
    truth_counts = Counter(truth.values())
    pred_counts = Counter(pred.values())
    h_truth = _entropy(list(truth_counts.values()), n)
    if h_truth == 0:
        return 1.0
    h_truth_given_pred = _conditional_entropy(contingency, dict(pred_counts), n)
    return 1.0 - (h_truth_given_pred / h_truth)


def completeness(truth: dict[str, str], pred: dict[str, str]) -> float:
    """
    1 - H(pred | truth) / H(pred). 1.0 = all members of each true class
    are assigned to the same predicted cluster (no false splits).
    """
    n = len(truth)
    if n == 0:
        return 1.0
    contingency: dict[tuple[str, str], int] = defaultdict(int)
    for item, t in truth.items():
        contingency[(pred[item], t)] += 1
    pred_counts = Counter(pred.values())
    truth_counts = Counter(truth.values())
    h_pred = _entropy(list(pred_counts.values()), n)
    if h_pred == 0:
        return 1.0
    h_pred_given_truth = _conditional_entropy(contingency, dict(truth_counts), n)
    return 1.0 - (h_pred_given_truth / h_pred)


def singleton_recall(truth: dict[str, str], pred: dict[str, str]) -> float:
    """
    Fraction of ground-truth singletons that the clusterer kept singleton.

    A "true singleton" is an item whose truth-campaign has exactly one
    member (lone wolves, background noise scanners). The metric exists
    because ARI/homogeneity/completeness all dilute the cost of a
    clusterer that absorbs noise into real campaigns — and noise
    absorption is the failure mode that makes campaign attribution
    useless in practice.
    """
    truth_counts = Counter(truth.values())
    true_singletons = [item for item, t in truth.items() if truth_counts[t] == 1]
    if not true_singletons:
        return 1.0
    pred_counts = Counter(pred.values())
    kept = sum(1 for item in true_singletons if pred_counts[pred[item]] == 1)
    return kept / len(true_singletons)


def score(truth: dict[str, str], pred: dict[str, str]) -> dict[str, float]:
    """One-shot bundle the four metrics for fixture reports."""
    return {
        "adjusted_rand_index": adjusted_rand_index(truth, pred),
        "homogeneity": homogeneity(truth, pred),
        "completeness": completeness(truth, pred),
        "singleton_recall": singleton_recall(truth, pred),
    }
