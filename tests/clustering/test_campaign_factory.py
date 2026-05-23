# SPDX-License-Identifier: AGPL-3.0-or-later
"""Determinism + DSL-validation tests for the synthetic campaign factory."""
from __future__ import annotations

import pytest

from decnet.clustering.ukc import UKCPhase
from tests.factories.campaign_factory import (
    DSLValidationError,
    generate,
)


def _minimal_spec() -> dict:
    return {
        "campaign": {
            "id": "c-test",
            "actors": [{"id": "a-1", "asn": 64512}],
            "phases": [{"name": "delivery", "actor": "a-1"}],
            "duration_days": 1,
        }
    }


def test_generation_is_deterministic_given_seed() -> None:
    spec = _minimal_spec()
    a = generate(spec, seed=42)
    b = generate(spec, seed=42)
    # IDs are RNG-driven — same seed must produce identical IDs, not
    # merely identical structure. Otherwise federation gossip and
    # fixture diffing both break.
    assert [att.attacker_id for att in a.attackers] == [
        att.attacker_id for att in b.attackers
    ]
    assert [s.session_id for s in a.sessions] == [s.session_id for s in b.sessions]


def test_different_seeds_produce_different_ids() -> None:
    spec = _minimal_spec()
    a = generate(spec, seed=1)
    b = generate(spec, seed=2)
    assert a.attackers[0].attacker_id != b.attackers[0].attacker_id


def test_truth_labels_match_dsl() -> None:
    spec = _minimal_spec()
    corpus = generate(spec, seed=0)
    assert corpus.attackers[0].truth_campaign_id == "c-test"
    assert corpus.attackers[0].truth_actor_id == "a-1"
    # truth_labels() returns the dict the metric harness consumes.
    labels = corpus.truth_labels()
    assert labels[corpus.attackers[0].attacker_id] == "c-test"


def test_unobservable_phase_emits_no_events() -> None:
    spec = _minimal_spec()
    spec["campaign"]["phases"] = [
        {"name": "reconnaissance", "actor": "a-1"},  # pre-target, unobservable
        {"name": "delivery", "actor": "a-1"},
    ]
    corpus = generate(spec, seed=0)
    # Only the delivery phase should produce sessions.
    assert all(s.phase == UKCPhase.DELIVERY for s in corpus.sessions)
    assert len(corpus.sessions) == 1


def test_unknown_phase_name_raises() -> None:
    spec = _minimal_spec()
    spec["campaign"]["phases"] = [{"name": "make_coffee", "actor": "a-1"}]
    with pytest.raises(DSLValidationError, match="unknown UKC phase"):
        generate(spec, seed=0)


def test_phase_referencing_unknown_actor_raises() -> None:
    spec = _minimal_spec()
    spec["campaign"]["phases"] = [{"name": "delivery", "actor": "ghost"}]
    with pytest.raises(DSLValidationError, match="unknown actor"):
        generate(spec, seed=0)


def test_noise_scanners_are_truth_singletons() -> None:
    spec = {
        "corpus": {
            "campaigns": [_minimal_spec()],
            "noise": {"scanner_count": 5},
        }
    }
    corpus = generate(spec, seed=0)
    # 1 campaign actor + 5 noise scanners = 6 distinct truth campaigns.
    truth_campaigns = {a.truth_campaign_id for a in corpus.attackers}
    assert len(truth_campaigns) == 6


def test_multi_actor_campaign_shares_campaign_id() -> None:
    spec = {
        "campaign": {
            "id": "c-shared",
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
    # Both attacker rows must point to the SAME truth_campaign_id —
    # this is the property fixture 5 (multi_operator) hinges on.
    assert set(truth.values()) == {"c-shared"}


# ─── ip_pool: rotating — identity-resolution fixture support ────────────────


def test_rotating_ip_pool_emits_one_row_per_rotation_count() -> None:
    """
    ``rotation_count: 5`` produces 5 SyntheticAttacker rows for that
    one DSL actor. Sticky default still produces 1.
    """
    spec = {
        "campaign": {
            "id": "c-rotating",
            "actors": [{
                "id": "a-1",
                "asn": 14061,
                "ip_pool": "rotating",
                "rotation_count": 5,
                "ja3": "JA3-fixed",
                "hassh": "HASSH-fixed",
            }],
            "phases": [{"name": "delivery", "actor": "a-1",
                        "target_selector": {"count": 10}}],
            "duration_days": 1,
        }
    }
    corpus = generate(spec, seed=0)
    assert len(corpus.attackers) == 5


def test_rotating_rows_share_identity_and_fingerprints_but_differ_on_ip() -> None:
    """
    All rotated rows MUST share truth_identity_id, truth_actor_id,
    truth_campaign_id, ja3, hassh — these are the stable signals the
    clusterer uses to recover identity. They MUST differ on ip — that's
    what makes the test interesting.
    """
    spec = {
        "campaign": {
            "id": "c-vpn-hop",
            "actors": [{
                "id": "a-1",
                "asn": 14061,
                "ip_pool": "rotating",
                "rotation_count": 5,
                "ja3": "JA3-fixed",
                "hassh": "HASSH-fixed",
            }],
            "phases": [{"name": "delivery", "actor": "a-1",
                        "target_selector": {"count": 5}}],
            "duration_days": 1,
        }
    }
    corpus = generate(spec, seed=0)
    rows = corpus.attackers
    # Stable: shared across all 5 rows.
    assert len({r.truth_identity_id for r in rows}) == 1
    assert len({r.truth_actor_id for r in rows}) == 1
    assert len({r.truth_campaign_id for r in rows}) == 1
    assert len({r.ja3 for r in rows}) == 1
    assert len({r.hassh for r in rows}) == 1
    # Rotating: 5 distinct IPs.
    assert len({r.ip for r in rows}) == 5


def test_rotation_asns_distributed_across_rows() -> None:
    """
    When ``rotation_asns`` is provided, each rotated row gets the
    corresponding ASN (cycling if shorter than rotation_count).
    """
    spec = {
        "campaign": {
            "id": "c-multi-asn",
            "actors": [{
                "id": "a-1",
                "asn": 14061,  # primary, ignored when rotation_asns is set
                "ip_pool": "rotating",
                "rotation_count": 5,
                "rotation_asns": [14061, 7922, 16509, 14618, 13335],
                "ja3": "x", "hassh": "y",
            }],
            "phases": [{"name": "delivery", "actor": "a-1",
                        "target_selector": {"count": 5}}],
            "duration_days": 1,
        }
    }
    corpus = generate(spec, seed=0)
    asns = [r.asn for r in corpus.attackers]
    assert asns == [14061, 7922, 16509, 14618, 13335]


def test_rotation_asns_cycle_when_shorter_than_count() -> None:
    """rotation_asns of length 2 with rotation_count=5 cycles."""
    spec = {
        "campaign": {
            "id": "c-cycle",
            "actors": [{
                "id": "a-1",
                "ip_pool": "rotating",
                "rotation_count": 5,
                "rotation_asns": [100, 200],
                "ja3": "x", "hassh": "y",
            }],
            "phases": [{"name": "delivery", "actor": "a-1"}],
            "duration_days": 1,
        }
    }
    corpus = generate(spec, seed=0)
    assert [r.asn for r in corpus.attackers] == [100, 200, 100, 200, 100]


def test_sessions_distribute_round_robin_across_rotated_rows() -> None:
    """
    With rotation_count=3 and 9 sessions in a phase, each row should
    receive 3 sessions (round-robin). This is what makes the clusterer
    job realistic — every observation row carries its own session
    timeline that the clusterer joins via shared fingerprints.
    """
    spec = {
        "campaign": {
            "id": "c-rr",
            "actors": [{
                "id": "a-1",
                "ip_pool": "rotating",
                "rotation_count": 3,
                "ja3": "x", "hassh": "y",
            }],
            "phases": [{"name": "delivery", "actor": "a-1",
                        "target_selector": {"count": 9}}],
            "duration_days": 1,
        }
    }
    corpus = generate(spec, seed=0)
    counts = sorted(len(r.sessions) for r in corpus.attackers)
    assert counts == [3, 3, 3]


def test_truth_labels_at_identity_level() -> None:
    """
    corpus.truth_labels(level="identity") returns the identity-level
    oracle the clusterer is scored against. Rotated rows for one DSL
    actor share an identity label even though they have distinct
    attacker_ids.
    """
    spec = {
        "campaign": {
            "id": "c-rot",
            "actors": [{
                "id": "a-1",
                "ip_pool": "rotating",
                "rotation_count": 4,
                "ja3": "x", "hassh": "y",
            }],
            "phases": [{"name": "delivery", "actor": "a-1",
                        "target_selector": {"count": 4}}],
            "duration_days": 1,
        }
    }
    corpus = generate(spec, seed=0)
    identity_labels = corpus.truth_labels(level="identity")
    assert len(identity_labels) == 4  # one per attacker row
    # All 4 attackers share one identity label.
    assert len(set(identity_labels.values())) == 1


def test_truth_labels_unknown_level_raises() -> None:
    spec = _minimal_spec()
    corpus = generate(spec, seed=0)
    with pytest.raises(ValueError, match="unknown truth-label level"):
        corpus.truth_labels(level="campaign-but-spelled-wrong")


def test_sticky_default_unchanged_back_compat() -> None:
    """
    The pre-existing sticky-default path produces exactly one row per
    actor and assigns truth_identity_id. Smoke-tests that the
    refactor didn't break the back-compat case.
    """
    corpus = generate(_minimal_spec(), seed=0)
    assert len(corpus.attackers) == 1
    assert corpus.attackers[0].truth_identity_id != ""
    # Default truth_labels still returns campaign labels.
    labels = corpus.truth_labels()
    assert set(labels.values()) == {"c-test"}


def test_rotated_sessions_carry_identity_label() -> None:
    """SyntheticSession.truth_identity_id matches its parent attacker."""
    spec = {
        "campaign": {
            "id": "c-rot",
            "actors": [{
                "id": "a-1",
                "ip_pool": "rotating",
                "rotation_count": 3,
                "ja3": "x", "hassh": "y",
            }],
            "phases": [{"name": "delivery", "actor": "a-1",
                        "target_selector": {"count": 6}}],
            "duration_days": 1,
        }
    }
    corpus = generate(spec, seed=0)
    by_id = {a.attacker_id: a for a in corpus.attackers}
    for sess in corpus.sessions:
        assert sess.truth_identity_id == by_id[sess.attacker_id].truth_identity_id
