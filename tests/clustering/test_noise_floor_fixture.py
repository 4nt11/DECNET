"""
End-to-end pipeline test for fixture 6 (noise_floor).

Composite corpus: bundles all five prior fixtures' campaigns + 10
Delivery-only noise scanners on top of lone_wolf's 8 inherited
ones. The fixture exists to catch cross-corpus interference —
signal collisions, factory ID re-use, clusterer ambiguity that
shows up only when multiple campaigns are scored together. Each
constituent fixture already ships its own in-fixture adversarial
test; fixture 6 covers a different failure class.

The composition is declared in `noise_floor.yaml` via an
``include_fixtures`` block (a fixture-6-specific format). The
loader in this test file expands it into a full
``corpus.campaigns`` spec at runtime, so the factory itself stays
unaware of the include mechanism.

Three tests cover this:

1. `test_noise_floor_corpus_integrity` — every constituent
   fixture's campaigns + actors are present in the merged corpus
   with their truth labels intact, and the 10 extra noise scanners
   are present alongside lone_wolf's 8 (truth-singletons all).

2. `test_noise_floor_pipeline_passes_bounds` — runs
   `composite_signals_clusterer` against the merged corpus.
   Approximates the planned similarity graph well enough that
   every campaign resolves and every singleton stays singleton.
   Trips the bound floors if any cross-fixture interference creeps
   in (signal collisions across fixtures' JA3/HASSH/C2 strings).

3. `test_noise_floor_singleton_recall_holds` — explicit assertion
   that every truth-singleton (the lone wolf, the 8 inherited noise
   scanners, the 10 extra noise scanners — 19 total) ends up in a
   singleton predicted cluster. Singleton recall is the load-
   bearing metric for this fixture.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.clustering.fixture_harness import (
    assert_fixture_bounds,
    composite_signals_clusterer,
)
from tests.clustering.metrics import score
from tests.factories.campaign_factory import generate, load_yaml

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "campaigns"
FIXTURE_YAML = FIXTURE_DIR / "noise_floor.yaml"
EXPECTED_YAML = FIXTURE_DIR / "noise_floor.expected.yaml"


def _expand_noise_floor_spec() -> dict[str, Any]:
    """Read noise_floor.yaml's include_fixtures block, load each
    constituent fixture, and merge their campaigns into one
    corpus-shaped spec. Returns a dict the factory's ``generate()``
    accepts as-is."""
    declared = yaml.safe_load(FIXTURE_YAML.read_text(encoding="utf-8"))
    campaigns: list[dict[str, Any]] = []
    inherited_noise = 0
    for fname in declared["include_fixtures"]:
        sub = load_yaml(FIXTURE_DIR / fname)
        if "corpus" in sub:
            campaigns.extend(sub["corpus"].get("campaigns", []))
            inherited_noise += int(
                (sub["corpus"].get("noise") or {}).get("scanner_count", 0)
            )
        else:
            campaigns.append({"campaign": sub["campaign"]})
    extra = int(declared.get("extra_noise_scanners", 0))
    return {
        "corpus": {
            "campaigns": campaigns,
            "noise": {"scanner_count": inherited_noise + extra},
        }
    }


def test_noise_floor_corpus_integrity() -> None:
    spec = _expand_noise_floor_spec()
    corpus = generate(spec, seed=0)

    truth_campaigns = {a.truth_campaign_id for a in corpus.attackers}

    # Every constituent fixture's campaign id appears in the merged
    # corpus. Any missing id means the loader dropped a fixture.
    expected_campaign_ids = {
        "shared-wordlist-A",
        "shared-wordlist-B",
        "vpn-hopping-001",
        "lone-wolf-001",
        "paused-campaign-001",
        "multi-operator-001",
    }
    assert expected_campaign_ids <= truth_campaigns, (
        f"missing campaign ids: {expected_campaign_ids - truth_campaigns}"
    )

    # Noise scanner count: 8 inherited from lone_wolf + 10 added.
    noise_attackers = [
        a for a in corpus.attackers
        if a.truth_campaign_id.startswith("noise-scanner-")
    ]
    assert len(noise_attackers) == 18

    # Every noise scanner is its own truth-campaign (singleton).
    noise_truth = {a.truth_campaign_id for a in noise_attackers}
    assert len(noise_truth) == 18

    # Real-campaign attackers: 2 (shared_wordlist) + 5 (vpn_hopping) +
    # 1 (lone_wolf wolf) + 2 (paused_campaign) + 2 (multi_operator)
    # = 12.
    real_attackers = [
        a for a in corpus.attackers
        if not a.truth_campaign_id.startswith("noise-scanner-")
    ]
    assert len(real_attackers) == 12, (
        f"expected 12 campaign-driven attackers, got {len(real_attackers)}"
    )


def test_noise_floor_pipeline_passes_bounds() -> None:
    spec = _expand_noise_floor_spec()
    corpus = generate(spec, seed=0)
    metrics = assert_fixture_bounds(corpus, composite_signals_clusterer, EXPECTED_YAML)
    # The combined corpus is heterogeneous — a perfect ARI is not
    # required (and the bound is loose at 0.85). Verify the harness
    # produced sensible numbers anyway.
    assert metrics["adjusted_rand_index"] >= 0.85
    assert metrics["singleton_recall"] >= 0.95


def test_noise_floor_singleton_recall_holds() -> None:
    """Every truth-singleton (lone wolf + 18 noise) must remain
    singleton under the composite clusterer. Noise absorption is the
    failure mode that makes campaign attribution useless in practice.
    """
    spec = _expand_noise_floor_spec()
    corpus = generate(spec, seed=0)
    pred = composite_signals_clusterer(corpus)

    truth = corpus.truth_labels(level="campaign")
    from collections import Counter
    truth_counts = Counter(truth.values())
    pred_counts = Counter(pred.values())

    true_singletons = [aid for aid, t in truth.items() if truth_counts[t] == 1]
    # Truth-singletons in this composite:
    #   1 lone wolf + 18 noise + 2 shared_wordlist actors (each
    #   campaign has one actor; campaign size 1 means truth-singleton)
    #   = 21.
    assert len(true_singletons) == 21, (
        f"expected 21 truth-singletons, got {len(true_singletons)}"
    )
    absorbed = [aid for aid in true_singletons if pred_counts[pred[aid]] != 1]
    assert not absorbed, (
        f"composite clusterer absorbed {len(absorbed)} singletons into "
        f"larger clusters: {absorbed[:5]}…"
    )

    metrics = score(truth, pred)
    assert metrics["singleton_recall"] == pytest.approx(1.0)
