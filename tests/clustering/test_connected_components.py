"""Tests for the connected-components clusterer (commit 4 — high-weight edges).

Covers, in order:

* The pure ``cluster_observations`` algorithm — singletons stay
  isolated, exact-match high-weight signals fold them together,
  un-fingerprinted observations stay un-mergeable.
* The production-row adapter ``from_attacker_row`` — JA3 / HASSH
  recovered from the fingerprints JSON; absent fields project to
  ``None``.
* End-to-end ``tick`` against a real SQLite repo: seeded attackers
  with shared / divergent fingerprints get the right identity rows
  written and the right ``identity_id`` links set.
* Three fixture-bound assertions: lone_wolf (pure singletons),
  shared_wordlist (no fingerprint signal — singletons), and
  vpn_hopping at identity-level (one identity from 5 rotated IPs
  via shared JA3 + HASSH).

The tick is bus-free here — the worker shell tests cover bus fan-out
separately. We're validating the algorithm + DB writes here.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from decnet.clustering.impl.connected_components import (
    ConnectedComponentsClusterer,
    cluster_observations,
    from_attacker_row,
)
from decnet.clustering.impl.similarity import Observation, from_synthetic
from decnet.web.db.factory import get_repository

FIXTURE_DIR = Path(__file__).parent.parent / "fixtures" / "campaigns"


# ─── pure algorithm ─────────────────────────────────────────────────────────


def _obs(obs_id: str, **kwargs) -> Observation:
    return Observation(observation_id=obs_id, **kwargs)


def test_cluster_observations_singletons_stay_isolated():
    a = _obs("a", ja3="ja3-a")
    b = _obs("b", ja3="ja3-b")
    c = _obs("c")  # no fingerprint
    labels = cluster_observations([a, b, c])
    assert labels["a"] != labels["b"]
    assert labels["b"] != labels["c"]
    assert labels["a"] != labels["c"]


def test_cluster_observations_ja3_match_unions():
    a = _obs("a", ja3="ja3-shared")
    b = _obs("b", ja3="ja3-shared")
    c = _obs("c", ja3="ja3-other")
    labels = cluster_observations([a, b, c])
    assert labels["a"] == labels["b"]
    assert labels["a"] != labels["c"]


def test_cluster_observations_unfingerprinted_stay_separate():
    """Two observations with no signals must NOT collapse into one
    cluster — that would fuse every noise scanner together."""
    a = _obs("a")
    b = _obs("b")
    labels = cluster_observations([a, b])
    assert labels["a"] != labels["b"]


def test_cluster_observations_transitive_via_payload():
    """A↔B via JA3, B↔C via payload → A, B, C all in one component."""
    a = _obs("a", ja3="ja3-x")
    b = _obs("b", ja3="ja3-x", payload_hashes=frozenset({"pl-1"}))
    c = _obs("c", payload_hashes=frozenset({"pl-1"}))
    labels = cluster_observations([a, b, c])
    assert labels["a"] == labels["b"] == labels["c"]


def test_cluster_observations_empty_input():
    assert cluster_observations([]) == {}


def test_cluster_observations_deterministic():
    """Same input → same labels. Load-bearing for fixture stability."""
    obs = [_obs("a", ja3="x"), _obs("b", ja3="x"), _obs("c")]
    assert cluster_observations(obs) == cluster_observations(obs)


# ─── production-row adapter ────────────────────────────────────────────────


def test_from_attacker_row_extracts_ja3_and_hassh():
    row = {
        "uuid": "att-1",
        "asn": 64500,
        "identity_id": None,
        "fingerprints": json.dumps([
            {"kind": "ja3", "hash": "ja3-abc"},
            {"kind": "hassh", "hash": "hassh-def"},
            {"kind": "jarm", "hash": "jarm-ghi"},  # not used in v1
        ]),
    }
    obs = from_attacker_row(row)
    assert obs.observation_id == "att-1"
    assert obs.ja3 == "ja3-abc"
    assert obs.hassh == "hassh-def"
    assert obs.asn == 64500


def test_from_attacker_row_handles_empty_fingerprints():
    row = {"uuid": "att-2", "asn": None, "identity_id": None, "fingerprints": "[]"}
    obs = from_attacker_row(row)
    assert obs.ja3 is None
    assert obs.hassh is None
    assert obs.asn is None


def test_from_attacker_row_handles_malformed_json():
    row = {"uuid": "att-3", "asn": None, "identity_id": None, "fingerprints": "not json"}
    obs = from_attacker_row(row)
    assert obs.ja3 is None
    assert obs.hassh is None


# ─── end-to-end tick against SQLite ────────────────────────────────────────


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "clusterer.db"))
    await r.initialize()
    return r


async def _seed_attacker(
    repo, ip: str, *,
    ja3: str | None = None, hassh: str | None = None, asn: int | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    fingerprints = []
    if ja3:
        fingerprints.append({"kind": "ja3", "hash": ja3})
    if hassh:
        fingerprints.append({"kind": "hassh", "hash": hassh})
    return await repo.upsert_attacker({
        "ip": ip,
        "first_seen": now,
        "last_seen": now,
        "event_count": 1,
        "asn": asn,
        "fingerprints": json.dumps(fingerprints),
    })


@pytest.mark.anyio
async def test_tick_on_empty_db_is_noop(repo):
    c = ConnectedComponentsClusterer()
    result = await c.tick(repo)
    assert result.identities_formed == []
    assert result.observations_linked == []


@pytest.mark.anyio
async def test_tick_clusters_shared_ja3(repo):
    """Two observations with the same JA3 → one identity row, both linked."""
    a = await _seed_attacker(repo, "1.1.1.1", ja3="ja3-x", asn=64500)
    b = await _seed_attacker(repo, "2.2.2.2", ja3="ja3-x", asn=64501)

    c = ConnectedComponentsClusterer()
    result = await c.tick(repo)

    assert len(result.identities_formed) == 1
    formed = result.identities_formed[0]
    assert set(formed["observation_uuids"]) == {a, b}

    # Identity row exists and both attackers FK to it.
    identity_uuid = formed["identity_uuid"]
    identity = await repo.get_identity_by_uuid(identity_uuid)
    assert identity is not None
    assert identity["uuid"] == identity_uuid

    obs_for_id = await repo.list_observations_for_identity(identity_uuid)
    obs_uuids = {o["uuid"] for o in obs_for_id}
    assert obs_uuids == {a, b}


@pytest.mark.anyio
async def test_tick_keeps_distinct_ja3_separate(repo):
    """Two divergent JA3s with no other shared signal → two singletons,
    no identity rows written (singletons stay un-clustered in v1)."""
    await _seed_attacker(repo, "1.1.1.1", ja3="ja3-a")
    await _seed_attacker(repo, "2.2.2.2", ja3="ja3-b")

    c = ConnectedComponentsClusterer()
    result = await c.tick(repo)

    # Singletons get identity rows of their own (one observation per cluster).
    assert len(result.identities_formed) == 2
    for formed in result.identities_formed:
        assert len(formed["observation_uuids"]) == 1


@pytest.mark.anyio
async def test_tick_links_new_observation_to_existing_identity(repo):
    """First tick: 2 attackers cluster into one identity. Second tick:
    a new attacker with the same JA3 should get linked, not minted."""
    a = await _seed_attacker(repo, "1.1.1.1", ja3="ja3-x")
    b = await _seed_attacker(repo, "2.2.2.2", ja3="ja3-x")

    c = ConnectedComponentsClusterer()
    first = await c.tick(repo)
    assert len(first.identities_formed) == 1
    identity_uuid = first.identities_formed[0]["identity_uuid"]

    # New observation arrives; same JA3.
    d = await _seed_attacker(repo, "3.3.3.3", ja3="ja3-x")

    second = await c.tick(repo)
    # No new identity should be formed for the existing component;
    # observation-linked should fire for the new one.
    formed_uuids = {f["identity_uuid"] for f in second.identities_formed}
    assert identity_uuid not in formed_uuids, (
        "second tick must link to the existing identity, not mint a new one"
    )
    linked_uuids = {l_["observation_uuid"] for l_ in second.observations_linked}
    assert d in linked_uuids


# ─── fixture-bound assertions (in-memory) ──────────────────────────────────


def _production_clusterer_predict(corpus) -> dict[str, str]:
    """Run the production cluster_observations over a corpus.

    Mirrors the reference clusterer signature (corpus → dict) so it can
    be passed to ``assert_fixture_bounds``. Pure / in-memory — does NOT
    touch the DB. The DB-side path is covered by the tick tests above.
    """
    obs = [from_synthetic(att) for att in corpus.attackers]
    labels = cluster_observations(obs)

    # Singletons (no shared signal) get unique cluster ids so the
    # metrics see them as distinct classes — matches the
    # fingerprint_clusterer reference shape on lone_wolf / shared_wordlist.
    pred: dict[str, str] = {}
    cluster_sizes: dict[str, int] = {}
    for cid in labels.values():
        cluster_sizes[cid] = cluster_sizes.get(cid, 0) + 1
    for obs_id, cid in labels.items():
        if cluster_sizes[cid] == 1:
            pred[obs_id] = f"cc-singleton-{obs_id}"
        else:
            pred[obs_id] = cid
    return pred


def test_lone_wolf_passes_with_production_clusterer():
    """Fixture 3: every actor singleton. The production clusterer
    keeps them all separate (no shared high-weight signal)."""
    from tests.clustering.fixture_harness import assert_fixture_bounds
    from tests.factories.campaign_factory import generate, load_yaml

    corpus = generate(load_yaml(FIXTURE_DIR / "lone_wolf.yaml"), seed=0)
    assert_fixture_bounds(
        corpus, _production_clusterer_predict,
        FIXTURE_DIR / "lone_wolf.expected.yaml",
    )


def test_shared_wordlist_passes_with_production_clusterer():
    """Fixture 1: two campaigns sharing only credentials, divergent
    infra. The production clusterer (high-weight edges only) keeps
    them separate — credential overlap is not a v1 signal yet."""
    from tests.clustering.fixture_harness import assert_fixture_bounds
    from tests.factories.campaign_factory import generate, load_yaml

    corpus = generate(load_yaml(FIXTURE_DIR / "shared_wordlist.yaml"), seed=0)
    assert_fixture_bounds(
        corpus, _production_clusterer_predict,
        FIXTURE_DIR / "shared_wordlist.expected.yaml",
    )


def test_paused_campaign_passes_with_production_clusterer():
    """Fixture 4: one campaign split across two operational windows by
    a multi-day silence. Both halves share JA3 + HASSH + payload + C2;
    the production clusterer must fold them into one identity. Time-
    agnostic invariant: the silence window is irrelevant to clustering."""
    from tests.clustering.fixture_harness import assert_fixture_bounds
    from tests.factories.campaign_factory import generate, load_yaml

    corpus = generate(load_yaml(FIXTURE_DIR / "paused_campaign.yaml"), seed=0)
    assert_fixture_bounds(
        corpus, _production_clusterer_predict,
        FIXTURE_DIR / "paused_campaign.expected.yaml",
    )


def test_multi_operator_keeps_distinct_identities_with_production_clusterer():
    """Fixture 5 at identity-level: two operators with distinct
    JA3 + HASSH, sharing C2 + payload. The production clusterer's
    fingerprint-disagreement veto must keep them as 2 identities."""
    from tests.factories.campaign_factory import generate, load_yaml
    from tests.clustering.metrics import score

    corpus = generate(load_yaml(FIXTURE_DIR / "multi_operator.yaml"), seed=0)
    pred = _production_clusterer_predict(corpus)
    # Two distinct truth identities; the production clusterer must
    # produce two distinct predicted clusters (no merge across
    # fingerprint-disagreeing operators).
    assert len(set(pred.values())) == 2
    metrics = score(corpus.truth_labels(level="identity"), pred)
    # Perfect identity-level recovery: ARI = 1.0, homogeneity = 1.0.
    assert metrics["adjusted_rand_index"] == pytest.approx(1.0)
    assert metrics["homogeneity"] == pytest.approx(1.0)


def test_cluster_observations_medium_alone_does_not_fuse():
    """Two observations sharing only command-sequence (medium-tier)
    must stay in distinct clusters — medium is a supporting signal."""
    a = Observation(
        observation_id="a",
        commands_by_phase={"discovery": ("ls", "id", "uname")},
    )
    b = Observation(
        observation_id="b",
        commands_by_phase={"discovery": ("ls", "id", "uname")},
    )
    labels = cluster_observations([a, b])
    assert labels["a"] != labels["b"]


def test_vpn_hopping_passes_at_identity_level_with_production_clusterer():
    """Fixture 2: one rotating actor with stable JA3 + HASSH across
    5 ASNs. The production clusterer must fold all 5 observations into
    one identity (high-weight JA3 / HASSH agreement)."""
    from tests.clustering.fixture_harness import assert_fixture_bounds
    from tests.factories.campaign_factory import generate, load_yaml

    corpus = generate(load_yaml(FIXTURE_DIR / "vpn_hopping.yaml"), seed=0)
    metrics = assert_fixture_bounds(
        corpus, _production_clusterer_predict,
        FIXTURE_DIR / "vpn_hopping.expected.yaml",
        truth_level="identity",
    )
    assert metrics["adjusted_rand_index"] == pytest.approx(1.0)
    assert metrics["completeness"] == pytest.approx(1.0)
