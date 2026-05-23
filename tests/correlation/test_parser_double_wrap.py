# SPDX-License-Identifier: AGPL-3.0-or-later
"""Correlation parser unwraps double-wrapped RFC5424 lines.

Mirrors ``tests/collector/test_parse_rfc5424_double_wrap.py``. Both
parsers read the same on-wire format; the profiler's ``parse_line``
must agree with the collector's ``parse_rfc5424`` so that
``Attacker.commands`` rows carry the real ``command`` event_type
(not the outer Docker envelope's NIL MSGID).
"""
from __future__ import annotations

from decnet.correlation.parser import parse_line


_DOUBLE_WRAPPED_CMD = (
    "<14>1 2026-05-02T06:22:48.089309+00:00 omega-decky 1 - - - "
    " 2026-05-02T06:22:48.089286+00:00 SRV-DELTA-77 bash - command "
    "[timeQuality tzKnown=\"1\" isSynced=\"1\" syncAccuracy=\"326228\"] "
    "CMD uid=0 user=root src=192.168.1.5 pwd=/root cmd=ls /var/www/html"
)


def test_double_wrapped_bash_cmd_event_type_is_command() -> None:
    e = parse_line(_DOUBLE_WRAPPED_CMD)
    assert e is not None
    assert e.event_type == "command"


def test_double_wrapped_bash_cmd_uses_inner_decky_and_service() -> None:
    e = parse_line(_DOUBLE_WRAPPED_CMD)
    assert e is not None
    assert e.decky == "SRV-DELTA-77"
    assert e.service == "bash"


def test_double_wrapped_bash_cmd_extracts_attacker_ip() -> None:
    e = parse_line(_DOUBLE_WRAPPED_CMD)
    assert e is not None
    assert e.attacker_ip == "192.168.1.5"


def test_double_wrapped_bash_cmd_extracts_command_field() -> None:
    """The behavioral profiler reads ``fields['command']`` for shell
    rules and the per-attacker ``commands`` rollup. Without it the
    R0001–R0030 pattern rules have no haystack."""
    e = parse_line(_DOUBLE_WRAPPED_CMD)
    assert e is not None
    assert e.fields.get("command") == "ls /var/www/html"


def test_single_wrapped_line_unchanged() -> None:
    line = (
        "<134>1 2026-05-02T06:00:25.453826+00:00 omega-decky smtp - "
        "disconnect [relay@55555 src_ip=\"192.168.1.5\"]"
    )
    e = parse_line(line)
    assert e is not None
    assert e.event_type == "disconnect"
    assert e.decky == "omega-decky"
    assert e.service == "smtp"
    assert e.attacker_ip == "192.168.1.5"


def test_outer_msgid_set_does_not_recurse() -> None:
    line = (
        "<134>1 2026-05-02T06:22:48.089309+00:00 omega-decky auth-helper - "
        "auth_attempt [relay@55555 username=\"root\" src_ip=\"192.168.1.5\"]"
    )
    e = parse_line(line)
    assert e is not None
    assert e.event_type == "auth_attempt"
    assert e.decky == "omega-decky"
    assert e.service == "auth-helper"
