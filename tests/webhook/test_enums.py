"""Unit tests for decnet.webhook.enums — simple→patterns expansion."""
from decnet.webhook.enums import (
    SIMPLE_EVENT_PATTERNS,
    expand_simple_events,
    merge_patterns,
)


def test_simple_event_patterns_covers_three_families():
    assert set(SIMPLE_EVENT_PATTERNS) == {
        "AttackerDetail",
        "DeckyStatus",
        "SystemStatus",
    }


def test_expand_single_event():
    assert expand_simple_events(["AttackerDetail"]) == ["attacker.>"]


def test_expand_multiple_events_concatenates():
    out = expand_simple_events(["AttackerDetail", "DeckyStatus"])
    assert out == ["attacker.>", "decky.*.state", "decky.*.traffic"]


def test_expand_unknown_event_dropped_silently():
    # The Literal type on the router rejects unknowns; this guards against
    # programmer error, not user input.
    assert expand_simple_events(["NotAThing"]) == []


def test_merge_dedups_overlap():
    merged = merge_patterns(["AttackerDetail"], ["attacker.>", "custom.>"])
    assert merged == ["attacker.>", "custom.>"]


def test_merge_preserves_order_simple_first():
    merged = merge_patterns(["SystemStatus"], ["attacker.>", "decky.*.state"])
    assert merged == ["system.>", "attacker.>", "decky.*.state"]


def test_merge_empty_lists_returns_empty():
    assert merge_patterns([], []) == []
    assert merge_patterns(None, None) == []


def test_merge_drops_empty_strings_and_non_strings():
    merged = merge_patterns([], ["", "attacker.>", None])  # type: ignore[list-item]
    assert merged == ["attacker.>"]
