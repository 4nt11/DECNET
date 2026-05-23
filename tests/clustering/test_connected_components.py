# SPDX-License-Identifier: AGPL-3.0-or-later
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
    ja3: str | None = None,
    hassh: str | None = None,
    asn: int | None = None,
    cert_sha256: str | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    # Two-shape fingerprint payload:
    #   - the "kind" entries feed the clusterer's from_attacker_row
    #     (test-fixture shape, line ~115 of connected_components.py)
    #   - the "bounty_type/payload" entries feed identity_rollup's
    #     extract_fp_summaries (production shape, written by the
    #     profiler from real bounty rows). Both shapes coexist in
    #     the same JSON list so the same seed exercises clustering
    #     AND the identity-column rollup.
    fingerprints: list[dict] = []
    if ja3:
        fingerprints.append({"kind": "ja3", "hash": ja3})
        fingerprints.append({
            "bounty_type": "fingerprint",
            "payload": {"fingerprint_type": "ja3", "ja3": ja3},
        })
    if hassh:
        fingerprints.append({"kind": "hassh", "hash": hassh})
        fingerprints.append({
            "bounty_type": "fingerprint",
            "payload": {"fingerprint_type": "hassh_server", "hash": hassh},
        })
    if cert_sha256:
        fingerprints.append({
            "bounty_type": "fingerprint",
            "payload": {
                "fingerprint_type": "tls_certificate",
                "cert_sha256": cert_sha256,
            },
        })
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
async def test_tick_merges_two_identities_when_component_spans_them(repo):
    """Two pre-existing identities whose observations now cluster
    together (e.g. a previously-missing fingerprint shows up) get
    soft-merged: the smaller-uuid identity wins, the loser's
    merged_into_uuid is set, observations stay FK'd to their
    original identity row."""
    # Tick 1: two distinct fingerprints → two distinct identities.
    a = await _seed_attacker(repo, "1.1.1.1", ja3="ja3-A")
    b = await _seed_attacker(repo, "2.2.2.2", ja3="ja3-B")

    c = ConnectedComponentsClusterer()
    first = await c.tick(repo)
    assert len(first.identities_formed) == 2

    # Snapshot the two identity uuids; we'll need them after the merge.
    identities_after_first = await repo.list_all_identities()
    assert len(identities_after_first) == 2
    uuids = sorted(i["uuid"] for i in identities_after_first)
    expected_winner, expected_loser = uuids[0], uuids[1]

    # Tick 2: a bridging observation — fingerprints match BOTH prior
    # rows. The bridge can't agree with both JA3s simultaneously, so
    # use a HASSH that matches A and a payload that matches B.
    # Simulate this with two new attackers, each linking a side.
    # Simpler: change attacker A's stored fingerprint to also include
    # ja3-B by re-seeding (in production this would be a fresh
    # observation that bridges them).
    bridge = await _seed_attacker(repo, "3.3.3.3", ja3="ja3-A", hassh="hassh-bridge")
    # Make B's row carry the same hassh so the bridge can union them.
    import json as _json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    await repo.upsert_attacker({
        "ip": "2.2.2.2", "first_seen": now, "last_seen": now,
        "event_count": 1,
        "fingerprints": _json.dumps([
            {"kind": "ja3", "hash": "ja3-B"},
            {"kind": "hassh", "hash": "hassh-bridge"},
        ]),
    })

    second = await c.tick(repo)
    assert len(second.identities_merged) == 1
    merge = second.identities_merged[0]
    assert merge["winner_uuid"] == expected_winner
    assert merge["loser_uuid"] == expected_loser

    # The loser's row still exists with merged_into_uuid set.
    all_after = {i["uuid"]: i for i in await repo.list_all_identities()}
    assert all_after[expected_loser]["merged_into_uuid"] == expected_winner
    assert all_after[expected_winner]["merged_into_uuid"] is None

    # Observations stay FK'd to their original identity row — the
    # merge is a soft pointer, NOT a re-point.
    a_row = await repo.get_attacker_by_uuid(a)
    b_row = await repo.get_attacker_by_uuid(b)
    assert a_row["identity_id"] in {expected_winner, expected_loser}
    assert b_row["identity_id"] in {expected_winner, expected_loser}


@pytest.mark.anyio
async def test_tick_unmerges_when_observations_diverge(repo):
    """Pre-seed a soft-merged pair, then change the underlying
    observations so they no longer cluster. The tick must clear
    merged_into_uuid and emit identities_unmerged."""
    import json as _json
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    # Two attackers with same JA3 → tick merges them via shared
    # high-tier signal (one identity formed).
    a = await _seed_attacker(repo, "1.1.1.1", ja3="ja3-shared")
    b = await _seed_attacker(repo, "2.2.2.2", ja3="ja3-shared")
    c = ConnectedComponentsClusterer()
    first = await c.tick(repo)
    assert len(first.identities_formed) == 1
    one_identity_uuid = first.identities_formed[0]["identity_uuid"]

    # Force a soft-merge state: split observation b out into its own
    # identity, then merge that back into the first via the repo
    # directly. This emulates a state the clusterer would have
    # arrived at across multiple ticks (form, then merge).
    second_uuid = "00000000-0000-0000-0000-00000000bbbb"
    await repo.create_attacker_identity({
        "uuid": second_uuid,
        "schema_version": 1,
        "first_seen_at": now, "last_seen_at": now,
        "created_at": now, "updated_at": now,
        "observation_count": 1,
    })
    await repo.set_attacker_identity_id(b, second_uuid)
    # Soft-merge second_uuid into one_identity_uuid (winner).
    winner = min(one_identity_uuid, second_uuid)
    loser = max(one_identity_uuid, second_uuid)
    if loser == one_identity_uuid:
        # Make the canonical mapping consistent with the test setup —
        # we need the merge to be "loser → winner" by min-uuid rule.
        # Swap ownership so the smaller-uuid keeps the active observations.
        await repo.set_attacker_identity_id(a, winner)
        await repo.set_attacker_identity_id(b, loser)
    await repo.update_identity_merged_into(loser, winner)

    # Verify the soft-merge is in place.
    pre = {i["uuid"]: i for i in await repo.list_all_identities()}
    assert pre[loser]["merged_into_uuid"] == winner

    # Now change the underlying fingerprints so a and b no longer cluster.
    await repo.upsert_attacker({
        "ip": "2.2.2.2", "first_seen": now, "last_seen": now,
        "event_count": 1,
        "fingerprints": _json.dumps([{"kind": "ja3", "hash": "ja3-different"}]),
    })

    # Tick should detect the divergence and revoke the merge.
    third = await c.tick(repo)
    assert len(third.identities_unmerged) == 1
    unmerged = third.identities_unmerged[0]
    assert unmerged["resurrected_uuid"] == loser
    assert unmerged["former_winner_uuid"] == winner

    post = {i["uuid"]: i for i in await repo.list_all_identities()}
    assert post[loser]["merged_into_uuid"] is None
    assert post[winner]["merged_into_uuid"] is None


@pytest.mark.anyio
async def test_tick_is_idempotent_under_no_changes(repo):
    """Running tick twice with no state changes between produces no
    side-effects on the second run."""
    await _seed_attacker(repo, "1.1.1.1", ja3="ja3-x")
    await _seed_attacker(repo, "2.2.2.2", ja3="ja3-x")
    await _seed_attacker(repo, "3.3.3.3", ja3="ja3-y")

    c = ConnectedComponentsClusterer()
    first = await c.tick(repo)
    second = await c.tick(repo)
    assert second.identities_formed == []
    assert second.observations_linked == []
    assert second.identities_merged == []
    assert second.identities_unmerged == []
    # Sanity: the first tick did do something.
    assert first.identities_formed


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


# ─── identity fingerprint rollup ───────────────────────────────────────────


@pytest.mark.anyio
async def test_tick_rolls_up_fingerprint_columns_on_create(repo):
    """A fresh-component tick must populate ja3_hashes / hassh_hashes /
    tls_cert_sha256 on the newly-minted identity row, deduplicated and
    sorted across all member observations."""
    await _seed_attacker(
        repo, "1.1.1.1", ja3="ja3-x", hassh="hassh-y", cert_sha256="ab" * 32,
    )
    await _seed_attacker(
        repo, "2.2.2.2", ja3="ja3-x", hassh="hassh-y", cert_sha256="cd" * 32,
    )
    c = ConnectedComponentsClusterer()
    result = await c.tick(repo)
    assert len(result.identities_formed) == 1
    identity_uuid = result.identities_formed[0]["identity_uuid"]

    rows = {i["uuid"]: i for i in await repo.list_all_identities()}
    identity = rows[identity_uuid]
    assert json.loads(identity["ja3_hashes"]) == ["ja3-x"]
    assert json.loads(identity["hassh_hashes"]) == ["hassh-y"]
    assert json.loads(identity["tls_cert_sha256"]) == sorted(["ab" * 32, "cd" * 32])


@pytest.mark.anyio
async def test_tick_rolls_up_fingerprints_on_link(repo):
    """When a new observation links into an existing identity, the
    rollup must reflect any new cert SHA-256 it brings."""
    await _seed_attacker(
        repo, "1.1.1.1", ja3="ja3-x", cert_sha256="ab" * 32,
    )
    c = ConnectedComponentsClusterer()
    first = await c.tick(repo)
    identity_uuid = first.identities_formed[0]["identity_uuid"]

    # New observation, same JA3, fresh cert.
    await _seed_attacker(
        repo, "2.2.2.2", ja3="ja3-x", cert_sha256="cd" * 32,
    )
    await c.tick(repo)

    rows = {i["uuid"]: i for i in await repo.list_all_identities()}
    identity = rows[identity_uuid]
    assert json.loads(identity["tls_cert_sha256"]) == sorted(["ab" * 32, "cd" * 32])


@pytest.mark.anyio
async def test_tick_leaves_columns_null_when_no_fingerprints(repo):
    """Two attackers with NO fingerprint signal cluster as separate
    singletons; their identity rows must keep all rollup columns NULL
    (not "[]" — NULL distinguishes 'no signal yet' from 'known empty')."""
    await _seed_attacker(repo, "1.1.1.1")
    await _seed_attacker(repo, "2.2.2.2")
    c = ConnectedComponentsClusterer()
    await c.tick(repo)

    for identity in await repo.list_all_identities():
        assert identity["ja3_hashes"] is None
        assert identity["hassh_hashes"] is None
        assert identity["tls_cert_sha256"] is None


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


def test_cluster_observations_credentials_alone_does_not_fuse():
    """Two observations sharing a credential set but nothing else
    must stay distinct. Fixture 1's failure mode in miniature."""
    a = Observation(
        observation_id="a",
        credentials=frozenset({("root", "toor"), ("admin", "admin")}),
    )
    b = Observation(
        observation_id="b",
        credentials=frozenset({("root", "toor"), ("admin", "admin")}),
    )
    labels = cluster_observations([a, b])
    assert labels["a"] != labels["b"]


def test_cluster_observations_asn_alone_does_not_fuse():
    """Two observations sharing only ASN must stay distinct.
    Fixture 2's failure mode in miniature — VPN/proxy hopping
    fragments ASN within a single identity, and ASN sharing
    across identities is common; can't drive clustering."""
    a = Observation(observation_id="a", asn=64500)
    b = Observation(observation_id="b", asn=64500)
    labels = cluster_observations([a, b])
    assert labels["a"] != labels["b"]


def test_cluster_observations_all_weak_signals_combined_does_not_fuse():
    """Even credentials + commands + ASN together don't drive
    clustering — only a high-tier signal does. Stack everything
    a campaign-level F1+F2 hybrid would have, confirm singletons."""
    a = Observation(
        observation_id="a",
        asn=64500,
        credentials=frozenset({("root", "toor"), ("admin", "admin")}),
        commands_by_phase={"discovery": ("ls", "id")},
    )
    b = Observation(
        observation_id="b",
        asn=64500,
        credentials=frozenset({("root", "toor"), ("admin", "admin")}),
        commands_by_phase={"discovery": ("ls", "id")},
    )
    labels = cluster_observations([a, b])
    assert labels["a"] != labels["b"]


def test_shared_wordlist_no_false_merge_at_identity_level():
    """F1 ratchet: even at identity level (where each row is its own
    identity), the production clusterer must not fuse credential-
    sharing observations. Tightens the F1 bound by asserting
    completeness == 1.0 at identity-level scoring (no truth identity
    is split, because every row is its own truth identity)."""
    from tests.factories.campaign_factory import generate, load_yaml
    from tests.clustering.metrics import score

    corpus = generate(load_yaml(FIXTURE_DIR / "shared_wordlist.yaml"), seed=0)
    pred = _production_clusterer_predict(corpus)
    metrics = score(corpus.truth_labels(level="identity"), pred)
    # Each row must land in its own predicted cluster — anything else
    # is a false merge driven by the credential-overlap signal.
    assert len(set(pred.values())) == len(corpus.attackers)
    assert metrics["homogeneity"] == pytest.approx(1.0)


def test_vpn_hopping_asn_alone_would_have_fragmented_but_doesnt():
    """F2 ratchet: vpn_hopping has 5 distinct ASNs across one identity.
    A clusterer that lets ASN drive would split into 5; the production
    clusterer doesn't because ASN is very-low-tier and JA3 / HASSH
    are stable. Confirms tier discipline holds end-to-end."""
    from tests.factories.campaign_factory import generate, load_yaml
    corpus = generate(load_yaml(FIXTURE_DIR / "vpn_hopping.yaml"), seed=0)
    pred = _production_clusterer_predict(corpus)
    asns = {a.asn for a in corpus.attackers}
    assert len(asns) == 5, "fixture sanity: 5 distinct ASNs"
    # All 5 land in one cluster, not 5.
    assert len(set(pred.values())) == 1


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


def _build_noise_floor_corpus():
    """Expand noise_floor.yaml's include_fixtures block into one corpus."""
    import yaml as _yaml
    from typing import Any
    from tests.factories.campaign_factory import generate, load_yaml

    declared = _yaml.safe_load(
        (FIXTURE_DIR / "noise_floor.yaml").read_text(encoding="utf-8")
    )
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
    spec = {"corpus": {
        "campaigns": campaigns,
        "noise": {"scanner_count": inherited_noise + extra},
    }}
    return generate(spec, seed=0)


def test_noise_floor_singleton_recall_holds_with_production_clusterer():
    """Fixture 6 ratchet — noise floor isolation.

    The load-bearing F6 invariant for the *production* clusterer:
    truth-singleton noise scanners must not be absorbed into real
    campaigns. A clusterer that pulls noise into campaigns dilutes
    attribution to nothing.

    Scored at *campaign* level so the truth-singleton noise scanners
    align with the prediction (each noise row has its own truth
    campaign id). Identity-level scoring is muddier here — see
    ``test_noise_floor_intra_campaign_recovery`` below for the
    constituent-campaign test that *is* identity-shaped.
    """
    from tests.clustering.metrics import score

    corpus = _build_noise_floor_corpus()
    pred = _production_clusterer_predict(corpus)
    metrics = score(corpus.truth_labels(level="campaign"), pred)
    assert metrics["singleton_recall"] >= 0.95, metrics


def test_noise_floor_intra_campaign_recovery_with_production_clusterer():
    """The other half of F6: real campaigns must still resolve through
    the noise. Specifically: vpn_hopping's 5 rotations land in one
    cluster (its identity-level signature), and shared_wordlist's two
    distinct campaigns stay un-merged despite sharing wordlists.
    Demonstrates the production clusterer's tier discipline holds
    under cross-corpus interference, not just per-fixture in
    isolation."""
    corpus = _build_noise_floor_corpus()
    pred = _production_clusterer_predict(corpus)

    # vpn_hopping: all 5 rotation rows fold into one predicted cluster.
    vpn_obs = [
        a.attacker_id for a in corpus.attackers
        if a.truth_campaign_id == "vpn-hopping-001"
    ]
    assert len(vpn_obs) == 5
    vpn_clusters = {pred[oid] for oid in vpn_obs}
    assert len(vpn_clusters) == 1, (
        "vpn_hopping must consolidate to one cluster across rotations"
    )

    # shared_wordlist A and B: distinct fingerprints → must stay
    # separate clusters despite shared credentials in the noise floor.
    sw_a = [
        a.attacker_id for a in corpus.attackers
        if a.truth_campaign_id == "shared-wordlist-A"
    ]
    sw_b = [
        a.attacker_id for a in corpus.attackers
        if a.truth_campaign_id == "shared-wordlist-B"
    ]
    assert sw_a and sw_b
    sw_a_clusters = {pred[oid] for oid in sw_a}
    sw_b_clusters = {pred[oid] for oid in sw_b}
    assert sw_a_clusters.isdisjoint(sw_b_clusters), (
        "shared_wordlist A and B must not share a cluster"
    )


def test_slow_burn_passes_with_production_clusterer():
    """Fixture 7 (slow_burn): one campaign across 3 multi-week operational
    windows. Shared JA3 + HASSH + C2 across all 3 actors. The production
    clusterer must fold them into one cluster — *despite* the multi-week
    silence between windows. Time-agnostic invariant in action."""
    from tests.clustering.fixture_harness import assert_fixture_bounds
    from tests.factories.campaign_factory import generate, load_yaml

    corpus = generate(load_yaml(FIXTURE_DIR / "slow_burn.yaml"), seed=0)
    metrics = assert_fixture_bounds(
        corpus, _production_clusterer_predict,
        FIXTURE_DIR / "slow_burn.expected.yaml",
    )
    pred = _production_clusterer_predict(corpus)
    # All three operational windows in one cluster — the F7 contract.
    assert len(set(pred.values())) == 1
    assert metrics["completeness"] == pytest.approx(1.0)


def test_slow_burn_time_shift_invariance():
    """Time-agnostic invariant in execution: shifting every observation's
    session timestamps by an arbitrary delta must not change the
    predicted clusters. This is the runtime counterpart of the
    Observation-no-time-fields static check in test_similarity.py."""
    from datetime import timedelta
    from tests.factories.campaign_factory import generate, load_yaml

    corpus = generate(load_yaml(FIXTURE_DIR / "slow_burn.yaml"), seed=0)
    baseline = _production_clusterer_predict(corpus)

    # Shift every session by +90 days (a full multi-month gap) and
    # re-cluster. Predicted membership must be identical.
    for att in corpus.attackers:
        att.first_seen += timedelta(days=90)
        att.last_seen += timedelta(days=90)
        for s in att.sessions:
            s.started_at += timedelta(days=90)

    shifted = _production_clusterer_predict(corpus)
    # Cluster ids may differ as opaque labels but membership groupings
    # must match. Convert each prediction to canonical form: a set of
    # frozensets of co-clustered observation_ids.
    def _canonical(pred: dict[str, str]) -> set[frozenset[str]]:
        groups: dict[str, set[str]] = {}
        for oid, cid in pred.items():
            groups.setdefault(cid, set()).add(oid)
        return {frozenset(g) for g in groups.values()}

    assert _canonical(baseline) == _canonical(shifted)


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
