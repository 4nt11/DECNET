# SPDX-License-Identifier: AGPL-3.0-or-later
"""E.3.18b — Worker fans `attacker.session.ended` into per-command events.

Pins the fan-out from ``development/TTP_TAGGING.md`` §"Worker shape" +
§"One event maps to many techniques": the R0001–R0030 shell rules
declare ``applies_to: [command]`` and match per command, not per
session. The worker translates one ``session.ended`` payload carrying a
``commands: list`` into:

    [TaggerEvent(source_kind="session", ...),
     TaggerEvent(source_kind="command", source_id="<id>", ...) * N]

so behavioral / cross-event lifters still see the session view AND the
:class:`RuleEngineTagger` (commit 3) sees one ``command`` event per
shell command.
"""
from __future__ import annotations

from decnet.bus import topics as _topics
from decnet.ttp.worker import _build_events


_TOPIC = _topics.attacker(_topics.ATTACKER_SESSION_ENDED)


def _payload_with(commands: object) -> dict[str, object]:
    return {
        "session_id": "sess-42",
        "attacker_uuid": "att-1",
        "identity_uuid": "id-1",
        "decky_id": "decky-7",
        "commands": commands,
    }


def test_session_without_commands_emits_only_session_event() -> None:
    events = _build_events(_TOPIC, {"session_id": "sess-42"})
    assert len(events) == 1
    assert events[0].source_kind == "session"


def test_session_with_string_commands_fans_out_one_per_command() -> None:
    events = _build_events(
        _TOPIC, _payload_with(["whoami", "id", "uname -a"]),
    )
    assert events[0].source_kind == "session"
    cmd_events = [e for e in events if e.source_kind == "command"]
    assert len(cmd_events) == 3
    assert [e.payload["command_text"] for e in cmd_events] == [
        "whoami", "id", "uname -a",
    ]
    # Per-command source_id must be unique so INSERT OR IGNORE on
    # compute_tag_uuid produces a distinct row per command.
    assert len({e.source_id for e in cmd_events}) == 3


def test_session_with_dict_commands_preserves_id_for_idempotency() -> None:
    events = _build_events(_TOPIC, _payload_with([
        {"id": "cmd-aaa", "command_text": "whoami"},
        {"command_id": "cmd-bbb", "command_text": "id"},
        {"uuid": "cmd-ccc", "command_text": "uname -a"},
    ]))
    cmd_events = [e for e in events if e.source_kind == "command"]
    assert [e.source_id for e in cmd_events] == ["cmd-aaa", "cmd-bbb", "cmd-ccc"]


def test_session_with_dict_commands_falls_back_to_synthetic_id() -> None:
    events = _build_events(
        _TOPIC, _payload_with([{"command_text": "whoami"}]),
    )
    cmd_events = [e for e in events if e.source_kind == "command"]
    assert len(cmd_events) == 1
    assert cmd_events[0].source_id.endswith("#cmd0")


def test_command_event_inherits_session_identifiers() -> None:
    events = _build_events(_TOPIC, _payload_with(["whoami"]))
    cmd = next(e for e in events if e.source_kind == "command")
    assert cmd.attacker_uuid == "att-1"
    assert cmd.identity_uuid == "id-1"
    assert cmd.session_id == "sess-42"
    assert cmd.decky_id == "decky-7"


def test_malformed_command_entries_are_skipped() -> None:
    events = _build_events(_TOPIC, _payload_with([
        "ok",
        42,                         # not a string/dict
        {"no_text_field": True},    # dict without command_text
        {"command_text": "good"},
    ]))
    cmd_events = [e for e in events if e.source_kind == "command"]
    assert [e.payload["command_text"] for e in cmd_events] == ["ok", "good"]


def test_non_session_topic_is_unchanged_by_fanout() -> None:
    events = _build_events(
        _topics.attacker(_topics.ATTACKER_INTEL_ENRICHED),
        {"attacker_uuid": "att-1", "verdict": "abuser"},
    )
    assert len(events) == 1
    assert events[0].source_kind == "intel"
