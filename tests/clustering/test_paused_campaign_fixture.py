"""
End-to-end pipeline test for fixture 4 (paused_campaign).

One campaign, two operational windows separated by a multi-day
silent stretch (days 3-5, 0-indexed [2, 4]). Modeled as two DSL
actors sharing JA3 + HASSH + payload + C2 callback — the
fingerprint-stable signals a real clusterer should resolve on.
Their ``active_days`` differ so each row's sessions land in
disjoint time ranges; this is what gives the adversarial
``time_window_clusterer`` something to fragment.

Three tests cover this:

1. `test_paused_campaign_corpus_shape` — sanity: 2 attackers, both
   share campaign id, sessions are time-disjoint across the pause
   window.

2. `test_paused_campaign_pipeline_passes_bounds` —
   `fingerprint_clusterer` reference folds both rows into one
   cluster (shared JA3 + HASSH). Trivially green at campaign-level
   scoring; the test is a ratchet point for the real algorithm.

3. `test_time_window_clusterer_fragments_campaign` — runs the
   deliberately-bad `time_window_clusterer`. With a 4-day silent
   stretch and a 1-day union threshold, the two halves cannot be
   bridged → 2 clusters → completeness collapses → bound rejected.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.clustering.fixture_harness import (
    assert_fixture_bounds,
    fingerprint_clusterer,
    time_window_clusterer,
)
from tests.clustering.metrics import score
from tests.factories.campaign_factory import generate, load_yaml

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "campaigns"
FIXTURE_YAML = FIXTURE_DIR / "paused_campaign.yaml"
EXPECTED_YAML = FIXTURE_DIR / "paused_campaign.expected.yaml"


def test_paused_campaign_corpus_shape() -> None:
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    assert len(corpus.attackers) == 2
    truth_campaigns = {a.truth_campaign_id for a in corpus.attackers}
    assert truth_campaigns == {"paused-campaign-001"}
    # Both rows share the operator's JA3 and HASSH — load-bearing
    # signal for fingerprint_clusterer to fold them.
    ja3s = {a.ja3 for a in corpus.attackers}
    hasshs = {a.hassh for a in corpus.attackers}
    assert len(ja3s) == 1
    assert len(hasshs) == 1
    # Each row's session timeline lives in its actor's active_days.
    rows_by_actor = {a.truth_actor_id: a for a in corpus.attackers}
    sprint_1 = rows_by_actor["ops-sprint-1"]
    sprint_2 = rows_by_actor["ops-sprint-2"]
    sprint_1_days = {s.started_at.day for s in sprint_1.sessions}
    sprint_2_days = {s.started_at.day for s in sprint_2.sessions}
    # Epoch is 2026-01-01; active_days [0,1] → calendar days 1,2;
    # active_days [5,6] → calendar days 6,7.
    assert sprint_1_days <= {1, 2}, f"sprint-1 leaked outside its window: {sprint_1_days}"
    assert sprint_2_days <= {6, 7}, f"sprint-2 leaked outside its window: {sprint_2_days}"


def test_paused_campaign_pipeline_passes_bounds() -> None:
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    metrics = assert_fixture_bounds(corpus, fingerprint_clusterer, EXPECTED_YAML)
    # Both rows share fingerprints → one predicted cluster.
    pred = fingerprint_clusterer(corpus)
    assert len(set(pred.values())) == 1
    # Truth = 1 campaign of 2 rows; pred = 1 cluster of 2 rows → ARI 1.0.
    assert metrics["adjusted_rand_index"] == pytest.approx(1.0)


def test_time_window_clusterer_fragments_campaign() -> None:
    """
    The fixture's reason for being. With a 4-day silence between
    the two operational windows and a 1-day union threshold, the
    bad clusterer cannot bridge the gap. The campaign splits in
    two and completeness collapses.

    If this test ever passes (time_window_clusterer satisfies the
    bounds), the fixture has lost its discrimination power.
    """
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    pred = time_window_clusterer(corpus, gap_days=1.0)
    assert len(set(pred.values())) == 2, (
        f"time-window clusterer should split into 2 clusters, got {len(set(pred.values()))}"
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


def test_time_window_clusterer_with_huge_gap_does_not_fragment() -> None:
    """
    Sanity for the time-window reference: with a gap larger than
    the campaign's silent stretch, the two halves union into one.
    Confirms the clusterer's behavior depends on the threshold,
    not on something unrelated. (Pause is days 3-5 → max separation
    between session ranges is ≈4 days; gap_days=10 must bridge.)
    """
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    pred = time_window_clusterer(corpus, gap_days=10.0)
    assert len(set(pred.values())) == 1


def test_silent_stretch_actually_silent() -> None:
    """No session may land inside the configured pause window."""
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    pause_calendar_days = {3, 4, 5}  # 1-indexed; pause_windows [[2,4]] in 0-indexed
    leaked = [
        s for s in corpus.sessions
        if s.started_at.day in pause_calendar_days
    ]
    assert not leaked, (
        f"sessions leaked into the silent stretch: "
        f"{[(s.session_id, s.started_at) for s in leaked]}"
    )
