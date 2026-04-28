"""Unit tests for :mod:`decnet.bus.base` — wildcard matching and the Event envelope."""
from __future__ import annotations

import pytest

from decnet.bus.base import EVENT_SCHEMA_VERSION, Event, matches


class TestMatches:
    @pytest.mark.parametrize("pattern,topic", [
        ("topology.abc.mutation.applied", "topology.abc.mutation.applied"),
        ("topology.*.mutation.applied", "topology.abc.mutation.applied"),
        ("topology.*.mutation.*", "topology.abc.mutation.applied"),
        ("topology.>", "topology.abc.mutation.applied"),
        ("topology.>", "topology.abc.status"),
        ("decky.*.state", "decky.xyz.state"),
        ("system.bus.health", "system.bus.health"),
    ])
    def test_matches_positive(self, pattern: str, topic: str) -> None:
        assert matches(pattern, topic) is True

    @pytest.mark.parametrize("pattern,topic", [
        ("topology.abc.mutation.applied", "topology.abc.mutation.failed"),
        ("topology.*", "topology.abc.mutation.applied"),       # * is one token
        ("topology.>", "topology"),                             # > needs ≥1 trailing
        ("decky.*.state", "decky.state"),                       # missing middle token
        ("decky.*.state", "decky.xyz.status"),
        ("a.b.c", "a.b"),
        ("a.b", "a.b.c"),
    ])
    def test_matches_negative(self, pattern: str, topic: str) -> None:
        assert matches(pattern, topic) is False


class TestEvent:
    def test_to_dict_round_trip(self) -> None:
        event = Event(topic="topology.abc.status", payload={"status": "active"}, type="status")
        data = event.to_dict()
        assert data["v"] == EVENT_SCHEMA_VERSION
        assert data["topic"] == "topology.abc.status"
        assert data["payload"] == {"status": "active"}
        assert data["type"] == "status"
        assert isinstance(data["id"], str)
        assert isinstance(data["ts"], float)

    def test_from_dict_prefers_wire_fields_but_ignores_topic(self) -> None:
        # The wire topic is the authoritative one (passed from the transport);
        # a malicious "topic" field in the body must be ignored.
        data = {
            "v": 1, "id": "abc", "type": "status",
            "topic": "attacker.spoofed",  # ignored
            "ts": 123.0,
            "payload": {"x": 1},
        }
        event = Event.from_dict("topology.abc.status", data)
        assert event.topic == "topology.abc.status"
        assert event.payload == {"x": 1}
        assert event.id == "abc"
        assert event.ts == 123.0

    def test_from_dict_tolerates_missing_fields(self) -> None:
        event = Event.from_dict("system.log", {})
        assert event.topic == "system.log"
        assert event.payload == {}
        assert event.v == EVENT_SCHEMA_VERSION
        assert event.id  # auto-generated
