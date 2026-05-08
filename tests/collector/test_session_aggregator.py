"""Collector session aggregator emits ``attacker.session.ended``.

Pins the producer-side fix that closes the gap surfaced in TTP
debugging: the TTP worker subscribes to ``attacker.session.ended`` but
no upstream component published it. The aggregator indexes shell
``command`` events per attacker_ip and emits one envelope per
``session_recorded`` event with the commands that fall inside the
session window.
"""
from __future__ import annotations

from typing import Any

import pytest

from decnet.bus import topics as _topics
from decnet.collector.worker import _SessionAggregator


_ATTACKER_IP = "192.168.1.5"


def _cmd(ts_iso: str, text: str) -> dict[str, Any]:
    return {
        "timestamp": ts_iso,
        "decky": "SRV-DELTA-77",
        "service": "bash",
        "event_type": "command",
        "attacker_ip": _ATTACKER_IP,
        "fields": {"command": text, "src": _ATTACKER_IP},
    }


def _raw_cmd(ts_iso: str, msg: str) -> dict[str, Any]:
    """Parsed event whose bash CMD body is in ``msg``, fields={}.

    Mirrors what the unmodified collector parser produces for
    PROMPT_COMMAND lines (the parser deliberately keeps fields empty
    so the frontend pill rendering doesn't double-up). The aggregator
    now extracts uid/user/src/pwd/command from that msg body.
    """
    return {
        "timestamp": ts_iso,
        "decky": "SRV-DELTA-77",
        "service": "bash",
        "event_type": "command",
        "attacker_ip": _ATTACKER_IP,
        "fields": {},
        "msg": msg,
    }


def _session_recorded(
    ts_iso: str, sid: str, duration_s: float = 60.0,
) -> dict[str, Any]:
    return {
        "timestamp": ts_iso,
        "decky": "omega-decky",
        "service": "sessrec",
        "event_type": "session_recorded",
        "attacker_ip": _ATTACKER_IP,
        "fields": {
            "sid": sid,
            "service": "ssh",
            "duration_s": str(duration_s),
            "src_ip": _ATTACKER_IP,
        },
    }


@pytest.fixture
def captured_publishes() -> list[tuple[str, dict[str, Any], str]]:
    return []


@pytest.fixture
def aggregator(
    captured_publishes: list[tuple[str, dict[str, Any], str]],
) -> _SessionAggregator:
    def _publish(topic: str, payload: dict[str, Any], event_type: str) -> None:
        captured_publishes.append((topic, payload, event_type))

    return _SessionAggregator(_publish, ttl_sec=3600.0)


# ── Indexing ────────────────────────────────────────────────────────


def test_command_events_are_indexed_per_attacker_ip(
    aggregator: _SessionAggregator,
) -> None:
    aggregator.add_event(_cmd("2026-05-02T06:22:48", "whoami"))
    aggregator.add_event(_cmd("2026-05-02T06:22:50", "id"))
    assert len(aggregator._cmds[_ATTACKER_IP]) == 2


def test_unknown_attacker_ip_is_ignored(
    aggregator: _SessionAggregator,
    captured_publishes: list[tuple[str, dict[str, Any], str]],
) -> None:
    bad = _cmd("2026-05-02T06:22:48", "whoami")
    bad["attacker_ip"] = "Unknown"
    aggregator.add_event(bad)
    assert aggregator._cmds == {}


def test_unparseable_timestamp_is_skipped(
    aggregator: _SessionAggregator,
) -> None:
    bad = _cmd("not-a-timestamp", "whoami")
    aggregator.add_event(bad)
    assert aggregator._cmds == {}


# ── Session emission ────────────────────────────────────────────────


def test_session_recorded_emits_attacker_session_ended(
    aggregator: _SessionAggregator,
    captured_publishes: list[tuple[str, dict[str, Any], str]],
) -> None:
    aggregator.add_event(_cmd("2026-05-02T06:22:48", "whoami"))
    aggregator.add_event(_cmd("2026-05-02T06:23:00", "id"))
    aggregator.add_event(_cmd("2026-05-02T06:23:10", "uname -a"))
    aggregator.add_event(_session_recorded(
        "2026-05-02T06:23:30", sid="sess-123", duration_s=120.0,
    ))

    assert len(captured_publishes) == 1
    topic, payload, event_type = captured_publishes[0]
    assert topic == _topics.attacker(_topics.ATTACKER_SESSION_ENDED)
    assert event_type == _topics.ATTACKER_SESSION_ENDED
    assert payload["session_id"] == "sess-123"
    assert payload["attacker_ip"] == _ATTACKER_IP
    assert payload["decky_id"] == "omega-decky"
    assert payload["service"] == "ssh"
    assert payload["duration_s"] == 120.0
    cmds = payload["commands"]
    assert [c["command_text"] for c in cmds] == ["whoami", "id", "uname -a"]
    assert [c["id"] for c in cmds] == [
        "sess-123#0", "sess-123#1", "sess-123#2",
    ]


def test_commands_outside_session_window_are_excluded(
    aggregator: _SessionAggregator,
    captured_publishes: list[tuple[str, dict[str, Any], str]],
) -> None:
    """duration_s window is [ended_at - duration_s, ended_at]."""
    # Old command from 10 minutes before the session — out of window
    # for a 60-second session.
    aggregator.add_event(_cmd("2026-05-02T06:13:00", "older-than-window"))
    # In-window
    aggregator.add_event(_cmd("2026-05-02T06:22:50", "whoami"))
    aggregator.add_event(_session_recorded(
        "2026-05-02T06:23:00", sid="s1", duration_s=60.0,
    ))
    payload = captured_publishes[0][1]
    cmd_texts = [c["command_text"] for c in payload["commands"]]
    assert "whoami" in cmd_texts
    assert "older-than-window" not in cmd_texts


def test_back_to_back_sessions_emit_distinct_envelopes(
    aggregator: _SessionAggregator,
    captured_publishes: list[tuple[str, dict[str, Any], str]],
) -> None:
    aggregator.add_event(_cmd("2026-05-02T06:22:50", "whoami"))
    aggregator.add_event(_session_recorded(
        "2026-05-02T06:23:00", sid="s1", duration_s=60.0,
    ))
    aggregator.add_event(_cmd("2026-05-02T06:30:00", "ls"))
    aggregator.add_event(_session_recorded(
        "2026-05-02T06:30:30", sid="s2", duration_s=60.0,
    ))
    assert len(captured_publishes) == 2
    s1, s2 = captured_publishes[0][1], captured_publishes[1][1]
    assert s1["session_id"] == "s1"
    assert s2["session_id"] == "s2"
    # The second session window is 60s — only "ls" lands in it.
    assert [c["command_text"] for c in s2["commands"]] == ["ls"]


def test_session_without_sid_falls_back_to_synthetic_id(
    aggregator: _SessionAggregator,
    captured_publishes: list[tuple[str, dict[str, Any], str]],
) -> None:
    aggregator.add_event(_cmd("2026-05-02T06:22:50", "whoami"))
    sr = _session_recorded("2026-05-02T06:23:00", sid="", duration_s=60.0)
    sr["fields"]["sid"] = ""
    aggregator.add_event(sr)
    payload = captured_publishes[0][1]
    assert payload["session_id"] is None
    cmd_id = payload["commands"][0]["id"]
    assert cmd_id.startswith(f"{_ATTACKER_IP}-2026-05-02T06:22:50")


# ── TTL eviction ────────────────────────────────────────────────────


def test_ttl_eviction_drops_old_commands() -> None:
    publishes: list[tuple[str, dict[str, Any], str]] = []

    def _publish(topic: str, payload: dict[str, Any], event_type: str) -> None:
        publishes.append((topic, payload, event_type))

    agg = _SessionAggregator(_publish, ttl_sec=10.0)
    agg.add_event(_cmd("2026-05-02T06:00:00", "old"))
    # New command 30 seconds later — TTL=10s, so the old one evicts.
    agg.add_event(_cmd("2026-05-02T06:00:30", "fresh"))
    remaining = [
        p.get("fields", {}).get("command")
        for _, p in agg._cmds[_ATTACKER_IP]
    ]
    assert remaining == ["fresh"]


def test_session_emits_structured_uid_user_src_pwd_when_msg_carries_them(
    aggregator: _SessionAggregator,
    captured_publishes: list[tuple[str, dict[str, Any], str]],
) -> None:
    """The bash PROMPT_COMMAND msg body splits into structured fields.

    Pins the "inspector wants UID/SRC/PWD/CMD on separate rows"
    contract. Without this the inspector sees one big
    ``CMD uid=0 user=root src=… cmd=…`` string and operators have to
    eyeball the cmd= portion out of the prefix garbage.
    """
    aggregator.add_event(_raw_cmd(
        "2026-05-02T06:22:48",
        "CMD uid=0 user=root src=192.168.1.5 pwd=/root "
        "cmd=nmap -p- 192.168.1.0/24",
    ))
    aggregator.add_event(_session_recorded(
        "2026-05-02T06:23:00", sid="sess-x", duration_s=120.0,
    ))
    payload = captured_publishes[0][1]
    cmd = payload["commands"][0]
    assert cmd["uid"] == "0"
    assert cmd["user"] == "root"
    assert cmd["src"] == "192.168.1.5"
    assert cmd["pwd"] == "/root"
    # ``command_text`` is the cmd= value, NOT the full "CMD uid=…" line.
    # nmap's command line carries spaces — we must preserve them.
    assert cmd["command_text"] == "nmap -p- 192.168.1.0/24"


def test_publish_failure_is_swallowed() -> None:
    """A blowing-up publish must not propagate into the stream thread."""
    def _bad(_t: str, _p: dict[str, Any], _e: str) -> None:
        raise RuntimeError("bus exploded")

    agg = _SessionAggregator(_bad, ttl_sec=3600.0)
    agg.add_event(_cmd("2026-05-02T06:22:50", "whoami"))
    # Should NOT raise.
    agg.add_event(_session_recorded("2026-05-02T06:23:00", sid="s1"))


# ── shard_path enrichment (W.1) ─────────────────────────────────────


def test_session_ended_payload_carries_shard_path_when_shard_exists(
    aggregator: _SessionAggregator,
    captured_publishes: list[tuple[str, dict[str, Any], str]],
    tmp_path,
    monkeypatch,
) -> None:
    """When find_shard_with_sid resolves, the payload carries the path."""
    import json
    from decnet.artifacts import shards

    sid = "11111111-2222-3333-4444-555555555555"
    shard_dir = tmp_path / "omega-decky" / "ssh" / "transcripts"
    shard_dir.mkdir(parents=True)
    shard = shard_dir / "sessions-2026-05-02.jsonl"
    shard.write_text(json.dumps({"sid": sid, "hdr": {}}) + "\n")

    monkeypatch.setattr(shards, "ARTIFACTS_ROOT", tmp_path)
    shards._INDEX_CACHE.clear()

    aggregator.add_event(_cmd("2026-05-02T06:22:48", "whoami"))
    aggregator.add_event(_session_recorded(
        "2026-05-02T06:23:00", sid=sid, duration_s=120.0,
    ))

    payload = captured_publishes[0][1]
    assert payload["shard_path"] == str(shard.resolve())


def test_session_ended_payload_shard_path_none_when_unresolvable(
    aggregator: _SessionAggregator,
    captured_publishes: list[tuple[str, dict[str, Any], str]],
    tmp_path,
    monkeypatch,
) -> None:
    """No shard on disk → shard_path is None (consumer skips honestly)."""
    from decnet.artifacts import shards
    monkeypatch.setattr(shards, "ARTIFACTS_ROOT", tmp_path)
    shards._INDEX_CACHE.clear()

    aggregator.add_event(_cmd("2026-05-02T06:22:48", "whoami"))
    aggregator.add_event(_session_recorded(
        "2026-05-02T06:23:00", sid="ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb",
    ))

    payload = captured_publishes[0][1]
    assert payload["shard_path"] is None
