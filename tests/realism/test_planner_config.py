"""Operator-tunable planner knobs (apply_payload / current_payload).

§3c of the realism handoff: the planner reads mutable module globals
that an admin can override via PUT /api/v1/realism/config. These tests
pin the validation surface and the payload roundtrip so a regression
that breaks operator tunables surfaces here, not on a live fleet.
"""
from __future__ import annotations

import pytest

from decnet.realism import planner
from decnet.realism.taxonomy import ContentClass


@pytest.fixture(autouse=True)
def _reset_after_each_test():
    yield
    planner.reset_to_defaults()


def test_current_payload_returns_defaults_after_reset():
    planner.reset_to_defaults()
    payload = planner.current_payload()
    assert payload["canary_probability"] == pytest.approx(0.03)
    user = {e["content_class"]: e["weight"] for e in payload["user_class_weights"]}
    assert user[ContentClass.NOTE.value] == 30
    assert user[ContentClass.TODO.value] == 20


def test_apply_payload_overrides_user_weights():
    planner.apply_payload({
        "user_class_weights": [
            {"content_class": "note", "weight": 5},
            {"content_class": "todo", "weight": 95},
        ],
    })
    payload = planner.current_payload()
    weights = {e["content_class"]: e["weight"] for e in payload["user_class_weights"]}
    assert weights == {"note": 5, "todo": 95}
    # System weights left untouched by a partial body.
    assert payload["system_class_weights"]


def test_apply_payload_overrides_canary_probability():
    planner.apply_payload({"canary_probability": 0.15})
    assert planner.current_payload()["canary_probability"] == pytest.approx(0.15)


def test_apply_payload_rejects_bad_canary_probability():
    with pytest.raises(ValueError, match="canary_probability"):
        planner.apply_payload({"canary_probability": 1.5})
    with pytest.raises(ValueError, match="canary_probability"):
        planner.apply_payload({"canary_probability": -0.1})
    with pytest.raises(ValueError, match="canary_probability"):
        planner.apply_payload({"canary_probability": "high"})


def test_apply_payload_rejects_negative_weight():
    with pytest.raises(ValueError, match="non-negative integer"):
        planner.apply_payload({
            "user_class_weights": [{"content_class": "note", "weight": -1}],
        })


def test_apply_payload_rejects_unknown_content_class():
    with pytest.raises(ValueError, match="unknown content_class"):
        planner.apply_payload({
            "user_class_weights": [{"content_class": "vibes", "weight": 1}],
        })


def test_apply_payload_drops_class_from_wrong_list():
    """A canary class on the user list is silently dropped (operator
    error), not raised — the partial save still applies the legit
    entries. Roundtrip shows the operator their entry didn't land."""
    planner.apply_payload({
        "user_class_weights": [
            {"content_class": "note", "weight": 10},
            {"content_class": "canary_aws_creds", "weight": 100},
        ],
    })
    weights = {
        e["content_class"]: e["weight"]
        for e in planner.current_payload()["user_class_weights"]
    }
    assert weights == {"note": 10}
    # canary class did NOT bleed onto the user list.
    assert "canary_aws_creds" not in weights


def test_apply_payload_rejects_zero_total_weight():
    with pytest.raises(ValueError, match="positive number"):
        planner.apply_payload({
            "user_class_weights": [{"content_class": "note", "weight": 0}],
        })


def test_apply_payload_partial_failure_leaves_state_intact():
    """If validation rejects part of a payload, the planner's other
    fields must not have been silently rebound."""
    planner.apply_payload({"canary_probability": 0.10})
    pre = planner.current_payload()

    with pytest.raises(ValueError):
        planner.apply_payload({
            "user_class_weights": [{"content_class": "note", "weight": 5}],
            "canary_probability": 9.0,  # invalid
        })

    post = planner.current_payload()
    assert post == pre  # nothing rebound on failure


def test_apply_payload_ignores_unknown_keys():
    """Forward-compat: future fields land without breaking older clients."""
    planner.apply_payload({"future_knob": "ignored"})
    # Nothing changed.
    assert planner.current_payload()["canary_probability"] == pytest.approx(0.03)
