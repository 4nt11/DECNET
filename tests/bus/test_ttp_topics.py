"""Bus topic naming tests for the TTP family (CDD step E.2.3).

Pins the wire vocabulary the worker (E.1.7), the API router (E.3.8),
and downstream SIEM consumers compile against. All assertions are
GREEN today — the constants and builders ship in
``decnet/bus/topics.py`` already; this test enforces that future
edits don't drift the names or break the wildcard contract.
"""
from __future__ import annotations

import pytest

from decnet.bus import topics
from decnet.bus.base import matches


# ─── Constant identity ───────────────────────────────────────────────────────


def test_ttp_leaf_constants() -> None:
    assert topics.TTP_TAGGED == "tagged"
    assert topics.TTP_RULE_FIRED == "rule.fired"
    assert topics.TTP_RULE_SUPPRESSED == "rule.suppressed"


def test_email_received_is_one_nats_token() -> None:
    # The leaf must carry NO embedded dot; the bus tokenizer would
    # otherwise split it into two segments and break the
    # ``email.<event>`` hierarchy. Pinned at the constant level so a
    # future edit "received.full" trips this test before it ships.
    assert topics.EMAIL_RECEIVED == "received"
    assert "." not in topics.EMAIL_RECEIVED


# ─── Built topics ────────────────────────────────────────────────────────────


def test_ttp_builder_produces_documented_strings() -> None:
    assert topics.ttp(topics.TTP_TAGGED) == "ttp.tagged"
    assert topics.ttp(topics.TTP_RULE_FIRED) == "ttp.rule.fired"
    assert topics.ttp(topics.TTP_RULE_SUPPRESSED) == "ttp.rule.suppressed"


def test_ttp_rule_fired_per_technique() -> None:
    assert topics.ttp_rule_fired("T1110") == "ttp.rule.fired.T1110"
    assert topics.ttp_rule_fired("T1059") == "ttp.rule.fired.T1059"


def test_email_topic_builder() -> None:
    assert topics.email_topic(topics.EMAIL_RECEIVED) == "email.received"


def test_ttp_builder_rejects_empty() -> None:
    with pytest.raises(ValueError):
        topics.ttp("")


# ─── Wildcard subscription contract ──────────────────────────────────────────


@pytest.mark.parametrize("topic", [
    "ttp.tagged",
    "ttp.rule.fired",
    "ttp.rule.fired.T1110",
    "ttp.rule.suppressed",
])
def test_ttp_wildcard_matches_every_documented_topic(topic: str) -> None:
    assert matches("ttp.>", topic) is True


def test_ttp_wildcard_excludes_root() -> None:
    # ``>`` requires AT LEAST one trailing token. The bare root
    # ``ttp`` must not match — pinned so a regression in
    # decnet.bus.base.matches() (e.g. allowing zero-token suffix)
    # is caught here.
    assert matches("ttp.>", "ttp") is False


def test_ttp_rule_fired_wildcard_per_technique() -> None:
    assert matches("ttp.rule.fired.>", "ttp.rule.fired.T1110") is True
    assert matches("ttp.rule.fired.>", "ttp.rule.fired") is False


# ─── Sub-technique IDs are NOT topic segments ────────────────────────────────


def test_ttp_rule_fired_rejects_subtechnique_segment() -> None:
    # Sub-technique ids carry an embedded dot (T1110.001). Allowing
    # them as a topic segment would silently split the topic into two
    # tokens and break ``ttp.rule.fired.>`` subscribers. The builder
    # MUST reject — sub_technique_id rides the payload, never the
    # wire address. (Documented at decnet/bus/topics.py:474–485.)
    with pytest.raises(ValueError):
        topics.ttp_rule_fired("T1110.001")


@pytest.mark.parametrize("bad", ["", "has.dot", "has*wild", "has>wild", "with space"])
def test_ttp_rule_fired_rejects_bad_segments(bad: str) -> None:
    with pytest.raises(ValueError):
        topics.ttp_rule_fired(bad)
