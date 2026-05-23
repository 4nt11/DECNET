# SPDX-License-Identifier: AGPL-3.0-or-later
"""
End-to-end pipeline test for fixture 1 (shared_wordlist).

Two campaigns. Same SSH credential wordlist. Everything else divergent
— ASN, IPs, JA3, HASSH, active hours.

The fixture exists to defeat one specific failure mode: a clusterer
that leans on credential-list overlap as a primary signal. Commodity
wordlists (rockyou, defaults lists, top-1k common-credentials) are
shared by hundreds of unrelated actors — credential overlap alone
cannot identify a campaign.

Two tests cover this:

1. `test_shared_wordlist_pipeline_passes_bounds` — runs the placeholder
   identity clusterer against the fixture. Trivially green (each
   campaign has one actor → identity puts each in its own cluster).
   This is the ratchet point: when the real algorithm replaces the
   placeholder, this test must continue to pass.

2. `test_credential_jaccard_clusterer_fails_homogeneity` — runs a
   deliberately-bad clusterer that merges any two attackers whose
   credential sets overlap above 50% Jaccard. Proves the fixture
   actually catches what it's designed to catch: this clusterer DOES
   merge the two campaigns, and the fixture's homogeneity floor (0.90)
   is breached. If this test ever passes, our fixture or our metric
   harness is broken.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.clustering.fixture_harness import (
    assert_fixture_bounds,
    credential_jaccard_clusterer,
    identity_clusterer,
)
from tests.clustering.metrics import score
from tests.factories.campaign_factory import generate, load_yaml

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "campaigns"


def test_shared_wordlist_pipeline_passes_bounds() -> None:
    spec = load_yaml(FIXTURE_DIR / "shared_wordlist.yaml")
    corpus = generate(spec, seed=0)
    assert_fixture_bounds(
        corpus, identity_clusterer, FIXTURE_DIR / "shared_wordlist.expected.yaml"
    )


def test_shared_wordlist_corpus_shape() -> None:
    """Sanity: 2 campaigns × 1 actor = 2 attackers, 4 sessions
    (delivery + credential_access × 3 sessions per campaign)."""
    spec = load_yaml(FIXTURE_DIR / "shared_wordlist.yaml")
    corpus = generate(spec, seed=0)
    assert len(corpus.attackers) == 2
    truth = corpus.truth_labels()
    assert set(truth.values()) == {"shared-wordlist-A", "shared-wordlist-B"}
    # Each attacker should have at least one credential_access session
    # whose credentials_tried is the full shared list.
    for att in corpus.attackers:
        cred_sessions = [s for s in att.sessions if s.credentials_tried]
        assert cred_sessions, f"attacker {att.attacker_id} has no credential sessions"
        # All cred sessions should carry the same 8-entry wordlist.
        for s in cred_sessions:
            assert len(s.credentials_tried) == 8


def test_credential_jaccard_clusterer_fails_homogeneity() -> None:
    """
    The fixture's reason for being. A naive clusterer that merges on
    credential-set Jaccard ≥ 0.5 will fuse the two campaigns (Jaccard
    = 1.0 on shared wordlists). That fusion drives homogeneity to 0
    — exactly the failure mode the fixture protects against.

    If this test ever PASSES (i.e. the bad clusterer scores high on
    this fixture), the fixture has lost its discrimination power and
    needs to be re-examined.
    """
    spec = load_yaml(FIXTURE_DIR / "shared_wordlist.yaml")
    corpus = generate(spec, seed=0)
    pred = credential_jaccard_clusterer(corpus, threshold=0.5)
    metrics = score(corpus.truth_labels(), pred)
    # The two campaigns must be merged by this clusterer.
    assert len(set(pred.values())) == 1, (
        "credential-Jaccard clusterer should merge both campaigns into one"
    )
    # And homogeneity must collapse — that's the signal a fixture-aware
    # CI gate would use to reject the bad clusterer.
    assert metrics["homogeneity"] == pytest.approx(0.0)


def test_naive_clusterer_does_not_fool_the_fixture() -> None:
    """
    Belt-and-braces: even though the bad clusterer collapses
    homogeneity, it might still pass *some* metrics (completeness is
    actually 1.0 — all members of each true campaign land in the
    single mega-cluster). The fixture's bound floor on homogeneity
    (0.90) must reject it.
    """
    spec = load_yaml(FIXTURE_DIR / "shared_wordlist.yaml")
    corpus = generate(spec, seed=0)
    pred = credential_jaccard_clusterer(corpus, threshold=0.5)
    metrics = score(corpus.truth_labels(), pred)
    bounds = {
        "adjusted_rand_index": 0.85,
        "homogeneity": 0.90,
        "completeness": 0.80,
        "singleton_recall": 0.95,
    }
    breaches = [k for k, floor in bounds.items() if metrics[k] < floor]
    assert "homogeneity" in breaches, (
        f"fixture failed to catch the bad clusterer; observed metrics: {metrics}"
    )
