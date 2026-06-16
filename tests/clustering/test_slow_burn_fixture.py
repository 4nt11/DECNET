# SPDX-License-Identifier: AGPL-3.0-or-later
"""
End-to-end pipeline test for fixture 7 (slow_burn).

90-day APT campaign with three operational windows separated by
multi-week silences. Models the real operational tempo of an APT
working a deep nested topology (MazeNET-style): recon over weeks,
exploitation later, action-on-objectives later still. The unique
signal this fixture stresses is TIME-AGNOSTIC IDENTITY — a
clusterer that silently expires old edges fragments any campaign
that operates over months.

Three tests cover this:

1. `test_slow_burn_corpus_shape` — sanity: 3 attackers, all share
   campaign id and operator fingerprint, sessions land in their
   respective operational windows.

2. `test_slow_burn_pipeline_passes_bounds` —
   `composite_signals_clusterer` (fingerprint OR C2 — time-agnostic)
   folds all three windows into one cluster.

3. `test_recency_decay_clusterer_fragments_campaign` — runs the
   deliberately-bad `recency_decay_clusterer` with a 14-day half-
   life and a 0.5 weight threshold. Edges between adjacent
   operational windows (24+ days apart) decay below threshold and
   drop. The campaign splits into three clusters; completeness
   collapses; the bound floor rejects the bad clusterer.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.clustering.fixture_harness import (
    assert_fixture_bounds,
    composite_signals_clusterer,
    recency_decay_clusterer,
)
from tests.clustering.metrics import score
from tests.factories.campaign_factory import generate, load_yaml

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "campaigns"
FIXTURE_YAML = FIXTURE_DIR / "slow_burn.yaml"
EXPECTED_YAML = FIXTURE_DIR / "slow_burn.expected.yaml"


def test_slow_burn_corpus_shape() -> None:
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    assert len(corpus.attackers) == 3
    truth_campaigns = {a.truth_campaign_id for a in corpus.attackers}
    assert truth_campaigns == {"slow-burn-001"}
    # Operator fingerprint stays stable across all three windows.
    ja3s = {a.ja3 for a in corpus.attackers}
    hasshs = {a.hassh for a in corpus.attackers}
    assert len(ja3s) == 1
    assert len(hasshs) == 1
    # Each row's sessions land in its operational window.
    by_actor = {a.truth_actor_id: a for a in corpus.attackers}
    recon_days = {s.started_at.timetuple().tm_yday for s in by_actor["ops-recon"].sessions}
    exploit_days = {s.started_at.timetuple().tm_yday for s in by_actor["ops-exploit"].sessions}
    action_days = {s.started_at.timetuple().tm_yday for s in by_actor["ops-action"].sessions}
    # Epoch is 2026-01-01 (day-of-year 1). active_days [7-11] →
    # day-of-year [8-12]; [35-39] → [36-40]; [75-79] → [76-80].
    assert recon_days <= {8, 9, 10, 11, 12}, recon_days
    assert exploit_days <= {36, 37, 38, 39, 40}, exploit_days
    assert action_days <= {76, 77, 78, 79, 80}, action_days


def test_slow_burn_pipeline_passes_bounds() -> None:
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    metrics = assert_fixture_bounds(corpus, composite_signals_clusterer, EXPECTED_YAML)
    pred = composite_signals_clusterer(corpus)
    assert len(set(pred.values())) == 1, (
        "composite_signals_clusterer should fold all three windows into one cluster"
    )
    assert metrics["adjusted_rand_index"] == pytest.approx(1.0)


def test_recency_decay_clusterer_fragments_campaign() -> None:
    """
    The fixture's reason for being. Recency decay with a 14-day
    half-life expires edges between operational windows that are
    24+ days apart, dropping their weight below the 0.5 threshold.
    The campaign fragments into three clusters; completeness
    collapses.

    If this test ever passes (the bad clusterer satisfies the
    bounds), the fixture has lost its discrimination power.
    """
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    pred = recency_decay_clusterer(corpus, half_life_days=14.0, threshold=0.5)
    assert len(set(pred.values())) == 3, (
        f"recency-decay clusterer should split into 3 clusters, "
        f"got {len(set(pred.values()))}"
    )

    metrics = score(corpus.truth_labels(level="campaign"), pred)
    assert metrics["completeness"] == pytest.approx(0.0)

    bounds = {
        "adjusted_rand_index": 0.85,
        "homogeneity": 0.90,
        "completeness": 0.80,
        "singleton_recall": 0.95,
    }
    breaches = [k for k, floor in bounds.items() if metrics[k] < floor]
    assert "completeness" in breaches, (
        f"fixture failed to catch the bad clusterer; observed metrics: {metrics}"
    )


def test_recency_decay_clusterer_with_long_halflife_does_not_fragment() -> None:
    """
    Sanity for the recency-decay reference: with a half-life longer
    than the campaign duration, every edge survives the decay. The
    three windows union into one. Confirms the clusterer's
    behavior depends on the half-life parameter, not on something
    unrelated. (Half-life 365 → edges across 40 days decay to
    ~0.93, well above the 0.5 threshold.)
    """
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    pred = recency_decay_clusterer(corpus, half_life_days=365.0, threshold=0.5)
    assert len(set(pred.values())) == 1
