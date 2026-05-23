# SPDX-License-Identifier: AGPL-3.0-or-later
"""
End-to-end pipeline test for fixture 5 (multi_operator).

One campaign, two operators with distinct UKC roles, distinct
tooling (different JA3 + HASSH), distinct ASNs and IPs, on
opposite shift schedules. What ties them is shared C2 callback +
shared stage-1 payload hash — the planned similarity graph's
"payload simhash + C2 endpoint match" arms are what should resolve
them as one campaign.

Three tests cover this:

1. `test_multi_operator_corpus_shape` — sanity: two attackers, one
   campaign, distinct fingerprints, shared C2 callback present in
   both rows' sessions, distinct shift hours.

2. `test_multi_operator_pipeline_passes_bounds` — runs
   `c2_callback_clusterer` (the appropriate pass-clusterer for
   this fixture, since fingerprint_clusterer would split the two
   distinct operators). Folds both rows into one cluster via the
   shared C2 endpoint.

3. `test_shift_clusterer_fragments_campaign` — runs the deliberately
   bad `shift_clusterer`. Actor A on night shift and Actor B on day
   shift split into two clusters → completeness collapses → the
   bound floor on completeness rejects the bad clusterer. This is
   the canonical proof that operational-schedule overlap is NOT a
   campaign signal.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.clustering.fixture_harness import (
    assert_fixture_bounds,
    c2_callback_clusterer,
    fingerprint_clusterer,
    shift_clusterer,
)
from tests.clustering.metrics import score
from tests.factories.campaign_factory import generate, load_yaml

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "campaigns"
FIXTURE_YAML = FIXTURE_DIR / "multi_operator.yaml"
EXPECTED_YAML = FIXTURE_DIR / "multi_operator.expected.yaml"


def test_multi_operator_corpus_shape() -> None:
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    assert len(corpus.attackers) == 2
    truth_campaigns = {a.truth_campaign_id for a in corpus.attackers}
    assert truth_campaigns == {"multi-operator-001"}
    # Two distinct fingerprints — the operators are different people
    # using different tools.
    ja3s = {a.ja3 for a in corpus.attackers}
    hasshs = {a.hassh for a in corpus.attackers}
    assert len(ja3s) == 2
    assert len(hasshs) == 2
    # Shared C2 callback across both rows' sessions.
    by_actor = {a.truth_actor_id: a for a in corpus.attackers}
    broker = by_actor["ops-broker-night"]
    postex = by_actor["ops-postex-day"]
    broker_c2s = {s.c2_callback for s in broker.sessions if s.c2_callback}
    postex_c2s = {s.c2_callback for s in postex.sessions if s.c2_callback}
    assert "c2.shared-op.example" in broker_c2s
    assert "c2.shared-op.example" in postex_c2s
    # Shifts are disjoint — load-bearing for the adversarial test.
    broker_hours = {s.started_at.hour for s in broker.sessions}
    postex_hours = {s.started_at.hour for s in postex.sessions}
    assert broker_hours <= {22, 23, 0, 1, 2, 3}
    assert postex_hours <= {9, 10, 11, 12, 13}


def test_multi_operator_pipeline_passes_bounds() -> None:
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    metrics = assert_fixture_bounds(corpus, c2_callback_clusterer, EXPECTED_YAML)
    pred = c2_callback_clusterer(corpus)
    assert len(set(pred.values())) == 1, (
        "c2_callback_clusterer should fold both operators into one cluster"
    )
    assert metrics["adjusted_rand_index"] == pytest.approx(1.0)


def test_fingerprint_clusterer_cannot_resolve_this_fixture() -> None:
    """
    Sanity for the harness, NOT a test of the clusterer: with two
    distinct fingerprints and one truth campaign,
    `fingerprint_clusterer` produces 2 clusters → completeness
    collapses. This is *why* the fixture's pass-clusterer is
    `c2_callback_clusterer` instead. Documents which signal
    actually carries the campaign here.
    """
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    pred = fingerprint_clusterer(corpus)
    assert len(set(pred.values())) == 2
    metrics = score(corpus.truth_labels(level="campaign"), pred)
    assert metrics["completeness"] == pytest.approx(0.0)


def test_shift_clusterer_fragments_campaign() -> None:
    """
    The fixture's reason for being. Bucket attackers by shift and
    the two operators land in 'night' and 'day' clusters → 2
    predicted clusters. Truth = 1 campaign → completeness collapses.

    If this test ever passes (shift_clusterer satisfies the bounds),
    the fixture has lost its discrimination power.
    """
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    pred = shift_clusterer(corpus)
    buckets = set(pred.values())
    assert buckets == {"shift-night", "shift-day"}, (
        f"expected one night cluster + one day cluster, got {buckets}"
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
