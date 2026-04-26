"""Unit tests for the similarity-graph primitives.

Each edge function is tested in isolation: agreement → high score,
disagreement → zero, missing-data → zero. Combination logic +
thresholds live in the connected-components impl and are covered by
the fixture suite once those land.
"""
from __future__ import annotations

import pytest

from decnet.clustering.impl.similarity import (
    EDGE_THRESHOLD,
    Observation,
    combined_edge_weight,
    from_synthetic,
    high_weight_edge,
    low_weight_edge,
    medium_weight_edge,
    very_low_weight_edge,
)


def _obs(**kwargs) -> Observation:
    """Build an Observation with sensible defaults for tests."""
    kwargs.setdefault("observation_id", "obs-x")
    return Observation(**kwargs)


# ─── high_weight_edge ──────────────────────────────────────────────────────


def test_high_weight_ja3_match():
    a = _obs(ja3="ja3-stable")
    b = _obs(ja3="ja3-stable")
    assert high_weight_edge(a, b) == 1.0


def test_high_weight_hassh_match():
    a = _obs(hassh="hassh-stable")
    b = _obs(hassh="hassh-stable")
    assert high_weight_edge(a, b) == 1.0


def test_high_weight_payload_hash_overlap():
    a = _obs(payload_hashes=frozenset({"pl-1", "pl-2"}))
    b = _obs(payload_hashes=frozenset({"pl-2", "pl-3"}))
    assert high_weight_edge(a, b) == 1.0


def test_high_weight_c2_overlap():
    a = _obs(c2_endpoints=frozenset({"c2.example.com"}))
    b = _obs(c2_endpoints=frozenset({"c2.example.com", "c2-alt.example.com"}))
    assert high_weight_edge(a, b) == 1.0


def test_high_weight_no_match():
    a = _obs(ja3="ja3-a", hassh="hassh-a", payload_hashes=frozenset({"x"}))
    b = _obs(ja3="ja3-b", hassh="hassh-b", payload_hashes=frozenset({"y"}))
    assert high_weight_edge(a, b) == 0.0


def test_high_weight_both_null_ja3_does_not_match():
    """Both-null JA3 must not be treated as 'agreement' — that would
    fuse every un-fingerprinted noise scanner into one mega-cluster."""
    a = _obs(ja3=None, hassh=None)
    b = _obs(ja3=None, hassh=None)
    assert high_weight_edge(a, b) == 0.0


# ─── fingerprint-disagreement veto on payload / C2 ──────────────────────────


def test_high_weight_veto_on_fingerprint_disagreement_with_shared_c2():
    """Fixture 5 protection: two operators with distinct JA3 + HASSH
    sharing a C2 endpoint must NOT score as identity match."""
    a = _obs(ja3="ja3-A", hassh="hassh-A",
             c2_endpoints=frozenset({"c2.shared.example"}))
    b = _obs(ja3="ja3-B", hassh="hassh-B",
             c2_endpoints=frozenset({"c2.shared.example"}))
    assert high_weight_edge(a, b) == 0.0


def test_high_weight_veto_on_fingerprint_disagreement_with_shared_payload():
    """Same shape, payload signal — also vetoed."""
    a = _obs(ja3="ja3-A", hassh="hassh-A",
             payload_hashes=frozenset({"stage1"}))
    b = _obs(ja3="ja3-B", hassh="hassh-B",
             payload_hashes=frozenset({"stage1"}))
    assert high_weight_edge(a, b) == 0.0


def test_high_weight_no_veto_when_fingerprints_unknown():
    """Two un-fingerprinted observations sharing C2 still cluster —
    we don't veto without evidence of disagreement."""
    a = _obs(c2_endpoints=frozenset({"c2.shared.example"}))
    b = _obs(c2_endpoints=frozenset({"c2.shared.example"}))
    assert high_weight_edge(a, b) == 1.0


def test_high_weight_no_veto_when_one_side_unknown():
    """One observation without fingerprints + one with — no
    disagreement evidence, so shared C2 still clusters."""
    a = _obs(ja3="ja3-A", hassh="hassh-A",
             c2_endpoints=frozenset({"c2.shared.example"}))
    b = _obs(c2_endpoints=frozenset({"c2.shared.example"}))
    assert high_weight_edge(a, b) == 1.0


def test_high_weight_partial_fingerprint_agreement_no_veto():
    """JA3 agrees, HASSH disagrees → some agreement → no veto. The
    veto only triggers on FULL disagreement."""
    a = _obs(ja3="ja3-shared", hassh="hassh-A",
             c2_endpoints=frozenset({"c2.shared.example"}))
    b = _obs(ja3="ja3-shared", hassh="hassh-B",
             c2_endpoints=frozenset({"c2.shared.example"}))
    # JA3 agreement returns 1.0 immediately; veto never reached.
    assert high_weight_edge(a, b) == 1.0


def test_high_weight_partial_disagreement_one_slot_only_vetoes():
    """One slot comparable + disagrees, other slot uncomparable
    (one side null) → veto triggers (only available evidence is
    disagreement)."""
    a = _obs(ja3="ja3-A", hassh=None,
             c2_endpoints=frozenset({"c2.shared.example"}))
    b = _obs(ja3="ja3-B", hassh=None,
             c2_endpoints=frozenset({"c2.shared.example"}))
    assert high_weight_edge(a, b) == 0.0


def test_high_weight_empty_sets_no_match():
    a = _obs(payload_hashes=frozenset(), c2_endpoints=frozenset())
    b = _obs(payload_hashes=frozenset(), c2_endpoints=frozenset())
    assert high_weight_edge(a, b) == 0.0


# ─── medium_weight_edge ────────────────────────────────────────────────────


def test_medium_weight_jaccard_full_match_in_one_phase():
    a = _obs(commands_by_phase={"discovery": ("ls", "id", "uname -a")})
    b = _obs(commands_by_phase={"discovery": ("ls", "id", "uname -a")})
    assert medium_weight_edge(a, b) == pytest.approx(1.0)


def test_medium_weight_jaccard_partial_match():
    a = _obs(commands_by_phase={"discovery": ("ls", "id", "uname -a", "whoami")})
    b = _obs(commands_by_phase={"discovery": ("ls", "id")})
    # |A∩B|=2, |A∪B|=4 → 0.5
    assert medium_weight_edge(a, b) == pytest.approx(0.5)


def test_medium_weight_picks_max_across_phases():
    a = _obs(commands_by_phase={
        "discovery": ("ls",),
        "exploitation": ("./payload", "chmod +x payload"),
    })
    b = _obs(commands_by_phase={
        "discovery": ("ps",),  # 0.0
        "exploitation": ("./payload", "chmod +x payload"),  # 1.0
    })
    assert medium_weight_edge(a, b) == pytest.approx(1.0)


def test_medium_weight_no_shared_phase_returns_zero():
    a = _obs(commands_by_phase={"discovery": ("ls",)})
    b = _obs(commands_by_phase={"exploitation": ("./payload",)})
    assert medium_weight_edge(a, b) == 0.0


def test_medium_weight_disjoint_commands_in_shared_phase():
    a = _obs(commands_by_phase={"discovery": ("ls",)})
    b = _obs(commands_by_phase={"discovery": ("ps",)})
    # |A∩B|=0, |A∪B|=2
    assert medium_weight_edge(a, b) == 0.0


def test_medium_weight_empty_corpora_returns_zero():
    a = _obs()
    b = _obs()
    assert medium_weight_edge(a, b) == 0.0


# ─── low_weight_edge ───────────────────────────────────────────────────────


def test_low_weight_credential_jaccard_match():
    a = _obs(credentials=frozenset({("root", "toor"), ("admin", "admin")}))
    b = _obs(credentials=frozenset({("root", "toor"), ("admin", "admin")}))
    assert low_weight_edge(a, b) == pytest.approx(1.0)


def test_low_weight_credential_partial_overlap():
    a = _obs(credentials=frozenset({("root", "toor"), ("admin", "admin")}))
    b = _obs(credentials=frozenset({("root", "toor"), ("user", "user")}))
    assert low_weight_edge(a, b) == pytest.approx(1 / 3)


def test_low_weight_no_credentials_returns_zero():
    a = _obs()
    b = _obs(credentials=frozenset({("root", "toor")}))
    assert low_weight_edge(a, b) == 0.0


# ─── very_low_weight_edge ──────────────────────────────────────────────────


def test_very_low_weight_asn_match():
    a = _obs(asn=64500)
    b = _obs(asn=64500)
    assert very_low_weight_edge(a, b) == 1.0


def test_very_low_weight_asn_mismatch():
    a = _obs(asn=64500)
    b = _obs(asn=64501)
    assert very_low_weight_edge(a, b) == 0.0


def test_very_low_weight_asn_null_returns_zero():
    a = _obs(asn=None)
    b = _obs(asn=64500)
    assert very_low_weight_edge(a, b) == 0.0


# ─── time-agnostic invariant ───────────────────────────────────────────────


def test_observations_carry_no_timestamps():
    """Compile-time guarantee: Observation has no time fields, so no
    edge function can accidentally start using them. Fixture 7 forbids
    recency-decay clustering."""
    field_names = set(Observation.__dataclass_fields__.keys())
    forbidden = {"first_seen", "last_seen", "started_at", "session_midpoint", "timestamp"}
    assert field_names.isdisjoint(forbidden), (
        f"Observation grew time fields: {field_names & forbidden}. "
        "Fixture 7 (slow_burn) forbids recency-aware clustering."
    )


# ─── from_synthetic adapter ────────────────────────────────────────────────


# ─── combined_edge_weight tier discipline ─────────────────────────────────


def test_combined_high_alone_crosses_threshold():
    a = _obs(ja3="ja3-shared")
    b = _obs(ja3="ja3-shared")
    assert combined_edge_weight(a, b) >= EDGE_THRESHOLD


def test_combined_medium_alone_below_threshold():
    """Single medium-tier match must NOT cluster — medium is a
    supporting signal, never a clustering driver on its own."""
    a = _obs(commands_by_phase={"discovery": ("ls", "id", "uname")})
    b = _obs(commands_by_phase={"discovery": ("ls", "id", "uname")})
    weight = combined_edge_weight(a, b)
    assert 0 < weight < EDGE_THRESHOLD


def test_combined_low_alone_below_threshold():
    """Credential-only overlap must NOT cluster — fixture 1's failure mode."""
    a = _obs(credentials=frozenset({("root", "toor"), ("admin", "admin")}))
    b = _obs(credentials=frozenset({("root", "toor"), ("admin", "admin")}))
    weight = combined_edge_weight(a, b)
    assert 0 < weight < EDGE_THRESHOLD


def test_combined_very_low_alone_below_threshold():
    """ASN-only overlap must NOT cluster — fixture 2's failure mode."""
    a = _obs(asn=64500)
    b = _obs(asn=64500)
    weight = combined_edge_weight(a, b)
    assert 0 < weight < EDGE_THRESHOLD


def test_combined_all_weak_tiers_still_below_threshold():
    """Even all three weaker tiers stacked don't reach threshold —
    only a high-tier signal does."""
    a = _obs(
        asn=64500,
        credentials=frozenset({("root", "toor")}),
        commands_by_phase={"discovery": ("ls",)},
    )
    b = _obs(
        asn=64500,
        credentials=frozenset({("root", "toor")}),
        commands_by_phase={"discovery": ("ls",)},
    )
    # 0.6*1.0 (medium) + 0.2*1.0 (low) + 0.05*1.0 (very_low) = 0.85
    weight = combined_edge_weight(a, b)
    assert weight < EDGE_THRESHOLD


def test_combined_high_plus_medium_clusters():
    a = _obs(ja3="ja3-x", commands_by_phase={"discovery": ("ls",)})
    b = _obs(ja3="ja3-x", commands_by_phase={"discovery": ("ls",)})
    assert combined_edge_weight(a, b) >= EDGE_THRESHOLD


def test_combined_no_signal_returns_zero():
    a = _obs()
    b = _obs()
    assert combined_edge_weight(a, b) == 0.0


def test_from_synthetic_round_trip():
    """The adapter projects a SyntheticAttacker into an Observation
    that the edge functions can score over."""
    from datetime import datetime, timezone
    from tests.factories.campaign_factory import (
        SyntheticAttacker, SyntheticSession,
    )
    from decnet.clustering.ukc import UKCPhase

    now = datetime.now(timezone.utc)
    sess = SyntheticSession(
        session_id="s1",
        attacker_id="a1",
        decky_id="d1",
        started_at=now,
        duration_s=10.0,
        phase=UKCPhase.DISCOVERY,
        commands=["ls", "id"],
        credentials_tried=[("root", "toor")],
        payload_hash="pl-1",
        c2_callback="c2.example.com",
        truth_campaign_id="c1",
        truth_actor_id="actor-1",
    )
    att = SyntheticAttacker(
        attacker_id="a1", ip="1.1.1.1", asn=64500,
        ja3="ja3-x", hassh="hassh-y",
        first_seen=now, last_seen=now,
        truth_campaign_id="c1", truth_actor_id="actor-1",
        sessions=[sess],
    )
    obs = from_synthetic(att)
    assert obs.observation_id == "a1"
    assert obs.ja3 == "ja3-x"
    assert obs.hassh == "hassh-y"
    assert obs.asn == 64500
    assert obs.payload_hashes == frozenset({"pl-1"})
    assert obs.c2_endpoints == frozenset({"c2.example.com"})
    assert obs.credentials == frozenset({("root", "toor")})
    assert obs.commands_by_phase == {"discovery": ("ls", "id")}
