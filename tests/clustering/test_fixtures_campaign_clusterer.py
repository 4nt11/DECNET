"""Run the production campaign clusterer through all 7 fixtures.

The 7 fixtures' YAML bounds were tuned for *reference* clusterers
(``c2_callback_clusterer``, ``composite_signals_clusterer``, etc.).
The production campaign clusterer (``ConnectedComponentsCampaignClusterer``)
is the system under test now; this module asserts it meets every
existing bound, plus a few stricter per-fixture invariants where the
algorithm should — by design — score perfectly.

The pure path is what's exercised here: ``cluster_identities``
operating over ``IdentityFeatures`` projected via
``from_synthetic_identity``. Each ``SyntheticAttacker`` is treated as
one identity (identity layer is below; the campaign clusterer reads
identities). End-to-end DB-backed validation is in
``test_campaign_worker.py``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from decnet.clustering.campaign.impl.connected_components import (
    cluster_identities,
)
from decnet.clustering.campaign.impl.similarity import (
    IdentityFeatures,
    from_synthetic_identity,
)
from decnet.clustering.impl.connected_components import cluster_observations
from decnet.clustering.impl.similarity import from_synthetic
from tests.clustering.fixture_harness import assert_fixture_bounds
from tests.clustering.metrics import score
from tests.factories.campaign_factory import generate, load_yaml

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "campaigns"


def _load_corpus(yaml_name: str) -> Any:
    """Load a fixture; expand the noise_floor composite if required."""
    path = FIXTURE_DIR / yaml_name
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if "include_fixtures" in raw:
        # Mirror tests/clustering/test_noise_floor_fixture.py's expander —
        # noise_floor is the only fixture that uses this format.
        campaigns: list[dict[str, Any]] = []
        inherited_noise = 0
        for fname in raw["include_fixtures"]:
            sub = load_yaml(FIXTURE_DIR / fname)
            if "corpus" in sub:
                campaigns.extend(sub["corpus"].get("campaigns", []))
                inherited_noise += int(
                    (sub["corpus"].get("noise") or {}).get("scanner_count", 0)
                )
            else:
                campaigns.append({"campaign": sub["campaign"]})
        extra = int(raw.get("extra_noise_scanners", 0))
        spec: Any = {
            "corpus": {
                "campaigns": campaigns,
                "noise": {"scanner_count": inherited_noise + extra},
            }
        }
        return generate(spec, seed=0)
    return generate(load_yaml(path), seed=0)


def production_campaign_clusterer(corpus) -> dict[str, str]:
    """Predict-fn adapter — chains identity + campaign clustering.

    Mirrors the production pipeline: the identity clusterer groups
    rotated-IP observations into identities, then the campaign
    clusterer groups identities into campaigns. The harness scores
    ``{attacker_id: cluster_id}`` so the chain preserves the
    attacker → identity → campaign mapping.
    """
    # ── Layer 1: identity clustering over observations.
    obs_list = [from_synthetic(a) for a in corpus.attackers]
    obs_labels = cluster_observations(obs_list)

    # Group attackers by their identity cluster.
    by_identity: dict[str, list] = {}
    for a in corpus.attackers:
        by_identity.setdefault(obs_labels[a.attacker_id], []).append(a)

    # ── Layer 2: aggregate each identity's member observations into
    # one ``IdentityFeatures``, run campaign clustering.
    identity_features: list[IdentityFeatures] = []
    for identity_id, members in by_identity.items():
        identity_features.append(_merge_features(identity_id, members))
    campaign_labels = cluster_identities(identity_features)

    # ── Map attacker_id → campaign cluster id via the identity hop.
    return {
        a.attacker_id: campaign_labels[obs_labels[a.attacker_id]]
        for a in corpus.attackers
    }


def _merge_features(identity_uuid: str, members) -> IdentityFeatures:
    """Aggregate per-attacker IdentityFeatures into a single identity.

    Set fields union; per-decky maps are merged (first/last seen
    extends across all member observations); session windows
    concatenate.
    """
    parts = [from_synthetic_identity(a, identity_uuid=identity_uuid) for a in members]

    asn_cohort: set[int] = set()
    payload_hashes: set[str] = set()
    c2_endpoints: set[str] = set()
    decky_set: set[str] = set()
    session_windows: list[tuple[float, float]] = []
    last_phase_per_decky: dict[str, str] = {}
    first_phase_per_decky: dict[str, str] = {}
    last_seen_per_decky: dict[str, float] = {}
    first_seen_per_decky: dict[str, float] = {}
    commands_by_phase_on_decky: dict[tuple[str, str], list[str]] = {}

    for p in parts:
        asn_cohort |= p.asn_cohort
        payload_hashes |= p.payload_hashes
        c2_endpoints |= p.c2_endpoints
        decky_set |= p.decky_set
        session_windows.extend(p.session_windows)
        for decky, ts in p.first_seen_per_decky.items():
            cur = first_seen_per_decky.get(decky)
            if cur is None or ts < cur:
                first_seen_per_decky[decky] = ts
                first_phase_per_decky[decky] = p.first_phase_per_decky.get(decky, "")
        for decky, ts in p.last_seen_per_decky.items():
            cur = last_seen_per_decky.get(decky)
            if cur is None or ts > cur:
                last_seen_per_decky[decky] = ts
                last_phase_per_decky[decky] = p.last_phase_per_decky.get(decky, "")
        for key, cmds in p.commands_by_phase_on_decky.items():
            commands_by_phase_on_decky.setdefault(key, []).extend(cmds)

    return IdentityFeatures(
        identity_uuid=identity_uuid,
        asn_cohort=frozenset(asn_cohort),
        payload_hashes=frozenset(payload_hashes),
        c2_endpoints=frozenset(c2_endpoints),
        decky_set=frozenset(decky_set),
        session_windows=tuple(session_windows),
        last_phase_per_decky=last_phase_per_decky,
        first_phase_per_decky=first_phase_per_decky,
        last_seen_per_decky=last_seen_per_decky,
        first_seen_per_decky=first_seen_per_decky,
        commands_by_phase_on_decky={
            k: tuple(v) for k, v in commands_by_phase_on_decky.items()
        },
    )


# ─── Per-fixture bound assertions ───────────────────────────────────────────


@pytest.mark.parametrize(
    "yaml_name,expected_name,truth_level",
    [
        ("lone_wolf.yaml", "lone_wolf.expected.yaml", "campaign"),
        ("shared_wordlist.yaml", "shared_wordlist.expected.yaml", "campaign"),
        ("vpn_hopping.yaml", "vpn_hopping.expected.yaml", "campaign"),
        ("paused_campaign.yaml", "paused_campaign.expected.yaml", "campaign"),
        ("multi_operator.yaml", "multi_operator.expected.yaml", "campaign"),
        ("noise_floor.yaml", "noise_floor.expected.yaml", "campaign"),
        ("slow_burn.yaml", "slow_burn.expected.yaml", "campaign"),
    ],
)
def test_production_campaign_clusterer_passes_fixture_bounds(
    yaml_name: str, expected_name: str, truth_level: str,
) -> None:
    corpus = _load_corpus(yaml_name)
    assert_fixture_bounds(
        corpus,
        production_campaign_clusterer,
        FIXTURE_DIR / expected_name,
        truth_level=truth_level,
    )


# ─── Per-fixture sharpness assertions (production clusterer specifics) ─────
#
# These tighten the YAML bounds for fixtures where the production
# clusterer is expected to score *perfectly*. They live as Python
# assertions (not YAML) so they only gate the production clusterer —
# the YAML bounds stay loose for the reference-clusterer tests in the
# per-fixture files. Ratcheting these up over time is safe; the YAML
# bounds remain the floor that *every* tested clusterer must beat.


def test_f3_lone_wolf_perfect_score() -> None:
    """Every actor a singleton — campaign clusterer should match."""
    corpus = _load_corpus("lone_wolf.yaml")
    pred = production_campaign_clusterer(corpus)
    metrics = score(corpus.truth_labels(level="campaign"), pred)
    assert metrics["singleton_recall"] == pytest.approx(1.0)
    assert metrics["adjusted_rand_index"] == pytest.approx(1.0)


def test_f1_shared_wordlist_no_false_merge() -> None:
    """Two campaigns burning the same wordlist must NOT fuse."""
    corpus = _load_corpus("shared_wordlist.yaml")
    pred = production_campaign_clusterer(corpus)
    truth = corpus.truth_labels(level="campaign")
    # Predicted: each truth-class member should have its own cluster id
    # (they share no payload / c2 / phase-handoff).
    truth_to_pred: dict[str, set[str]] = {}
    for aid, t in truth.items():
        truth_to_pred.setdefault(t, set()).add(pred[aid])
    # No predicted cluster spans two truth campaigns.
    pred_to_truth: dict[str, set[str]] = {}
    for aid, p in pred.items():
        pred_to_truth.setdefault(p, set()).add(truth[aid])
    assert all(len(s) == 1 for s in pred_to_truth.values()), (
        f"shared_wordlist: predicted cluster spans multiple campaigns: "
        f"{pred_to_truth}"
    )


def test_f5_multi_operator_folds_to_one_campaign() -> None:
    """Two operators with shared payload + C2 + phase-handoff fold to one campaign."""
    corpus = _load_corpus("multi_operator.yaml")
    pred = production_campaign_clusterer(corpus)
    cluster_ids = set(pred.values())
    assert len(cluster_ids) == 1, (
        f"multi_operator: expected 1 campaign, got {len(cluster_ids)} — "
        f"predictions: {pred}"
    )
    metrics = score(corpus.truth_labels(level="campaign"), pred)
    assert metrics["adjusted_rand_index"] == pytest.approx(1.0)


def test_f7_slow_burn_time_shift_invariance() -> None:
    """Shift every timestamp +90 days — predictions must be identical.

    The pure F7 invariant: campaign edges are pairwise-relative; an
    absolute shift on every session must not change any cluster
    assignment. Mirrors the identity-side check in
    ``test_slow_burn_fixture.py``.
    """
    from datetime import timedelta

    corpus = _load_corpus("slow_burn.yaml")
    base_pred = production_campaign_clusterer(corpus)

    delta = timedelta(days=90)
    for a in corpus.attackers:
        a.first_seen = a.first_seen + delta
        a.last_seen = a.last_seen + delta
        for s in a.sessions:
            s.started_at = s.started_at + delta

    shifted_pred = production_campaign_clusterer(corpus)

    # Cluster id labels are opaque — what matters is the partition.
    base_partition = _partition(base_pred)
    shifted_partition = _partition(shifted_pred)
    assert base_partition == shifted_partition, (
        f"slow_burn: +90d shift changed the predicted partition\n"
        f"base: {base_partition}\n"
        f"shifted: {shifted_partition}"
    )


def _partition(labels: dict[str, str]) -> set[frozenset[str]]:
    """Return the cluster partition (set of frozensets of member ids).

    Cluster id strings are arbitrary; the equivalence we care about is
    "which ids ended up in the same cluster?".
    """
    by_cluster: dict[str, set[str]] = {}
    for member, cluster_id in labels.items():
        by_cluster.setdefault(cluster_id, set()).add(member)
    return {frozenset(s) for s in by_cluster.values()}
