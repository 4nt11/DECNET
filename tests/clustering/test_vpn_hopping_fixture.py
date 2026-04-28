"""
End-to-end pipeline test for fixture 2 (vpn_hopping).

One campaign, one actor, ip_pool: rotating across 5 distinct ASNs.
JA3, HASSH, and payload_hash stable across every rotation. The
fixture is the canonical "same hands, different IP/ASN" scenario
that motivates Identity Resolution (see development/
IDENTITY_RESOLUTION.md — these are the signals "the attacker can't
cheaply rotate"). It also stresses the clusterer's weighting of
ASN: the real similarity graph weights ASN match "very low" because
VPN/proxy hopping shatters ASN within a single identity.

Three tests cover this:

1. `test_vpn_hopping_pipeline_passes_bounds_at_campaign_level` —
   `fingerprint_clusterer` reference folds all 5 rotated rows into
   one cluster (shared JA3 + HASSH). Trivially green at campaign-
   level scoring; the test is a ratchet point for the real algorithm
   to keep passing once it lands.

2. `test_vpn_hopping_pipeline_passes_bounds_at_identity_level` —
   same clusterer, scored against the identity-level oracle. Verifies
   the factory's `truth_identity_id` plumbing across rotated rows
   (commit f6b8375) actually expresses the right ground truth: 5
   observations → 1 identity.

3. `test_asn_clusterer_fragments_campaign` — runs the deliberately-
   bad `asn_clusterer` reference. The 5 rotation_asns become 5
   singleton clusters → completeness collapses to ~0, ARI collapses,
   and the fixture's bound floor on completeness (0.80) rejects the
   bad clusterer. If this test ever passes, the fixture has lost its
   discrimination power.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.clustering.fixture_harness import (
    asn_clusterer,
    assert_fixture_bounds,
    fingerprint_clusterer,
)
from tests.clustering.metrics import score
from tests.factories.campaign_factory import generate, load_yaml

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "campaigns"
FIXTURE_YAML = FIXTURE_DIR / "vpn_hopping.yaml"
EXPECTED_YAML = FIXTURE_DIR / "vpn_hopping.expected.yaml"


def test_vpn_hopping_corpus_shape() -> None:
    """One actor, rotation_count=5 → 5 observation rows, 1 identity, 1 campaign."""
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    assert len(corpus.attackers) == 5
    truth_campaigns = {a.truth_campaign_id for a in corpus.attackers}
    truth_identities = {a.truth_identity_id for a in corpus.attackers}
    truth_actors = {a.truth_actor_id for a in corpus.attackers}
    assert truth_campaigns == {"vpn-hopping-001"}
    assert len(truth_identities) == 1, "all 5 rotations must share one truth_identity_id"
    assert truth_actors == {"hopper-a"}
    asns = {a.asn for a in corpus.attackers}
    assert asns == {64512, 64513, 64514, 64515, 64516}
    ips = {a.ip for a in corpus.attackers}
    assert len(ips) == 5, "rotation must produce 5 distinct IPs"
    # Stable fingerprints across every row — the load-bearing signal.
    ja3s = {a.ja3 for a in corpus.attackers}
    hasshs = {a.hassh for a in corpus.attackers}
    assert len(ja3s) == 1
    assert len(hasshs) == 1


def test_vpn_hopping_pipeline_passes_bounds_at_campaign_level() -> None:
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    assert_fixture_bounds(corpus, fingerprint_clusterer, EXPECTED_YAML)


def test_vpn_hopping_pipeline_passes_bounds_at_identity_level() -> None:
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    metrics = assert_fixture_bounds(
        corpus, fingerprint_clusterer, EXPECTED_YAML, truth_level="identity"
    )
    # All 5 observations should land in the same predicted cluster
    # AND share one truth identity → ARI is exactly 1.0.
    assert metrics["adjusted_rand_index"] == pytest.approx(1.0)
    assert metrics["completeness"] == pytest.approx(1.0)


def test_asn_clusterer_fragments_campaign() -> None:
    """
    The fixture's reason for being. Group by ASN and the campaign
    shatters into 5 singletons — completeness goes to 0 because the
    one true class is split across 5 predicted clusters. The bound
    floor on completeness (0.80) must reject this.

    If this test ever passes (asn_clusterer satisfies the bounds),
    the fixture has lost its discrimination power.
    """
    spec = load_yaml(FIXTURE_YAML)
    corpus = generate(spec, seed=0)
    pred = asn_clusterer(corpus)
    # 5 distinct ASNs in the rotation → 5 distinct predicted clusters.
    assert len(set(pred.values())) == 5

    metrics = score(corpus.truth_labels(level="campaign"), pred)
    # Completeness collapses — that's the failure mode the fixture
    # protects against.
    assert metrics["completeness"] == pytest.approx(0.0)
    # ARI collapses too (very different partitions).
    assert metrics["adjusted_rand_index"] < 0.1

    # The bound floor would reject this clusterer.
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
