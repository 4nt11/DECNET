"""Classifier unit tests for decnet.correlation.event_kinds."""
from __future__ import annotations

from decnet.correlation.event_kinds import (
    INTERACTION_EVENT_TYPES,
    NOISE_EVENT_TYPES,
    bucket_services,
    classify_event,
)


def test_shell_family_classifies_as_interaction():
    for evt in ("command", "shell_input", "sql_query", "redis_command", "exec"):
        assert classify_event(evt) == "interaction", evt


def test_smtp_engagement_classifies_as_interaction():
    for evt in ("mail_from", "rcpt_to", "message_accepted"):
        assert classify_event(evt) == "interaction", evt


def test_file_and_pubsub_classify_as_interaction():
    for evt in ("file_captured", "upload", "retr", "publish", "subscribe"):
        assert classify_event(evt) == "interaction", evt


def test_noise_events_classify_as_noise():
    for evt in ("startup", "shutdown", "parse_error", "unknown_command"):
        assert classify_event(evt) == "noise", evt


def test_scan_touch_events_classify_as_scan():
    # These are common template verbs that don't cross into interaction
    # and aren't on the noise list.
    for evt in ("connection", "disconnect", "tls_client_hello", "auth_attempt",
                "banner", "get_request", "head_request"):
        assert classify_event(evt) == "scan", evt


def test_unknown_event_defaults_to_scan():
    # Conservative default: an unknown verb from a new template should
    # show up as "scanned" rather than over-credited as interaction.
    assert classify_event("some_future_verb") == "scan"
    assert classify_event("") == "scan"


def test_interaction_and_noise_sets_are_disjoint():
    assert INTERACTION_EVENT_TYPES.isdisjoint(NOISE_EVENT_TYPES)


def test_bucket_services_single_interaction_wins():
    # If a service has both scan-level and interaction-level events,
    # it counts as interacted (not scanned).
    pairs = [
        ("ssh", "connection"),       # scan
        ("ssh", "shell_input"),      # interaction → wins
    ]
    assert bucket_services(pairs) == {"interacted": ["ssh"], "scanned": []}


def test_bucket_services_noise_only_service_dropped():
    pairs = [("bus", "startup"), ("bus", "shutdown")]
    assert bucket_services(pairs) == {"interacted": [], "scanned": []}


def test_bucket_services_mixed_realistic():
    # Attacker A: scan-only on http + ssh.
    # Attacker B (same test but for one attacker's pairs): mixed.
    pairs = [
        ("http", "connection"),
        ("http", "get_request"),
        ("ssh", "connection"),
        ("ssh", "auth_attempt"),
        ("ssh", "shell_input"),      # promotes ssh to interacted
        ("ftp", "retr"),             # interaction
        ("mongo", "connection"),     # scan only
    ]
    result = bucket_services(pairs)
    assert result["interacted"] == ["ftp", "ssh"]
    assert result["scanned"] == ["http", "mongo"]


def test_bucket_services_empty_input():
    assert bucket_services([]) == {"interacted": [], "scanned": []}


def test_bucket_services_returns_sorted_lists():
    pairs = [("zzz", "command"), ("aaa", "command"), ("mmm", "connection")]
    result = bucket_services(pairs)
    assert result["interacted"] == ["aaa", "zzz"]  # alphabetical
    assert result["scanned"] == ["mmm"]
