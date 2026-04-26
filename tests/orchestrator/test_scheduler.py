"""Picker policy tests for the orchestrator scheduler."""
from __future__ import annotations

import secrets

import pytest

from decnet.orchestrator import scheduler


def _decky(uuid: str, name: str, ip: str | None, services: list[str] | str):
    return {"uuid": uuid, "name": name, "ip": ip, "services": services}


def test_pick_returns_none_when_no_ssh_deckies():
    deckies = [
        _decky("u1", "decky-01", "10.0.0.1", ["http"]),
        _decky("u2", "decky-02", "10.0.0.2", ["smb"]),
    ]
    assert scheduler.pick(deckies) is None


def test_pick_returns_none_when_ssh_decky_has_no_ip():
    deckies = [_decky("u1", "decky-01", None, ["ssh"])]
    assert scheduler.pick(deckies) is None


def test_pick_file_action_with_single_ssh_decky():
    deckies = [_decky("u1", "decky-01", "10.0.0.1", ["ssh"])]
    rng = secrets.SystemRandom()
    rng.seed = lambda *_: None  # SystemRandom doesn't seed; ignore
    action = scheduler.pick(deckies, rand=rng)
    assert isinstance(action, scheduler.FileAction)
    assert action.dst_uuid == "u1"
    assert action.path.startswith("/")
    assert action.content


def test_pick_traffic_or_file_with_two_ssh_deckies():
    deckies = [
        _decky("u1", "decky-01", "10.0.0.1", ["ssh"]),
        _decky("u2", "decky-02", "10.0.0.2", ["ssh"]),
    ]
    seen_kinds: set[str] = set()
    # 50/50 split — 40 trials makes both kinds essentially certain
    for _ in range(40):
        action = scheduler.pick(deckies)
        assert action is not None
        seen_kinds.add("traffic" if isinstance(action, scheduler.TrafficAction) else "file")
        if isinstance(action, scheduler.TrafficAction):
            assert action.src_uuid != action.dst_uuid
            assert action.dst_ip in {"10.0.0.1", "10.0.0.2"}
            assert action.protocol == "ssh"
    assert seen_kinds == {"traffic", "file"}


def test_pick_skips_non_deserialised_services():
    """If services is still a JSON string (defensive), the decky is excluded."""
    deckies = [_decky("u1", "decky-01", "10.0.0.1", '["ssh"]')]
    assert scheduler.pick(deckies) is None
