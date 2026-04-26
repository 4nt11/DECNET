"""
End-to-end pipeline test for fixture 3 (lone_wolf).

Loads the YAML spec, runs the synthetic generator, applies a placeholder
identity clusterer (each attacker → its own cluster), scores against
the expected bounds. This is the simplest of the six fixtures and is
deliberately the first one wired up — its ground truth is all
singletons, so an identity clusterer trivially passes, which proves the
DSL→factory→metrics pipeline works before any real algorithm is built.

Once the connected-components clusterer (CAMPAIGN_CLUSTERING.md §4)
lands, this test will swap the placeholder for the real implementation
and the same fixture must continue to pass.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tests.clustering.metrics import score
from tests.factories.campaign_factory import GeneratedCorpus, generate, load_yaml

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "campaigns"


def _identity_clusterer(corpus: GeneratedCorpus) -> dict[str, str]:
    """Every attacker is its own cluster. Trivially correct on lone_wolf."""
    return {a.attacker_id: f"cluster-{a.attacker_id}" for a in corpus.attackers}


def test_lone_wolf_pipeline_passes_bounds() -> None:
    spec = load_yaml(FIXTURE_DIR / "lone_wolf.yaml")
    bounds = yaml.safe_load((FIXTURE_DIR / "lone_wolf.expected.yaml").read_text())

    corpus = generate(spec, seed=0)
    truth = corpus.truth_labels()
    pred = _identity_clusterer(corpus)
    metrics = score(truth, pred)

    failures = []
    for name, bound in bounds.items():
        observed = metrics[name]
        if observed < bound["min"]:
            failures.append(f"{name}={observed:.3f} < min {bound['min']:.3f}")
    assert not failures, "fixture bounds violated: " + "; ".join(failures)


def test_lone_wolf_corpus_shape() -> None:
    """Sanity: 1 wolf + 8 noise scanners = 9 attackers, 9 sessions."""
    spec = load_yaml(FIXTURE_DIR / "lone_wolf.yaml")
    corpus = generate(spec, seed=0)
    assert len(corpus.attackers) == 9
    assert len(corpus.sessions) == 9
    # Every attacker is a truth-singleton (its own campaign).
    truth_campaigns = {a.truth_campaign_id for a in corpus.attackers}
    assert len(truth_campaigns) == 9


def test_identity_clusterer_fails_on_a_real_campaign() -> None:
    """
    Sanity for the harness, NOT a test of the clusterer: a real
    multi-actor campaign should make the placeholder identity clusterer
    fail completeness, since each truth-campaign gets fragmented into
    one-member clusters. If this didn't fail, our metrics would be
    blind to false splits — and that's the entire point of fixture 4
    and 5 in the design doc.
    """
    spec = {
        "campaign": {
            "id": "c-real",
            "actors": [
                {"id": "a-1", "asn": 14061},
                {"id": "a-2", "asn": 14061},
            ],
            "phases": [
                {"name": "delivery", "actor": "a-1"},
                {"name": "discovery", "actor": "a-2"},
            ],
            "duration_days": 1,
        }
    }
    corpus = generate(spec, seed=0)
    truth = corpus.truth_labels()
    pred = _identity_clusterer(corpus)
    metrics = score(truth, pred)
    # Identity clusterer splits the one true campaign across 2 clusters
    # → completeness drops below 1.0. This must hold or our metrics
    # aren't catching what they're supposed to catch.
    assert metrics["completeness"] < 1.0
    assert metrics["homogeneity"] == pytest.approx(1.0)  # no false merges, just splits
