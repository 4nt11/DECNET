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
