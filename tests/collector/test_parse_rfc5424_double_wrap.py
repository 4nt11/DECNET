# SPDX-License-Identifier: AGPL-3.0-or-later
"""Collector parser unwraps double-wrapped RFC5424 lines.

Honeypot SSH containers export a ``PROMPT_COMMAND`` that calls
``logger --rfc5424 --msgid command -p user.info -t bash "CMD …"``.
The Docker-stdout reader prepends an outer RFC 5424 envelope around
that inner syslog line. Outer MSGID is NIL, so without an unwrap step
every shell command lands as ``event_type="-"`` in the collector
output and the TTP rule pack never sees it.
"""
from __future__ import annotations

from decnet.collector.worker import parse_rfc5424


_DOUBLE_WRAPPED_CMD = (
    "<14>1 2026-05-02T06:22:48.089309+00:00 omega-decky 1 - - - "
    " 2026-05-02T06:22:48.089286+00:00 SRV-DELTA-77 bash - command "
    "[timeQuality tzKnown=\"1\" isSynced=\"1\" syncAccuracy=\"326228\"] "
    "CMD uid=0 user=root src=192.168.1.5 pwd=/root cmd=ls /var/www/html"
)


def test_double_wrapped_bash_cmd_extracts_inner_msgid() -> None:
    p = parse_rfc5424(_DOUBLE_WRAPPED_CMD)
    assert p is not None
    assert p["event_type"] == "command"
    # decky / service come from the INNER header — not the outer
    # ``omega-decky`` / ``1`` Docker envelope fields.
    assert p["decky"] == "SRV-DELTA-77"
    assert p["service"] == "bash"


def test_double_wrapped_bash_cmd_recovers_attacker_ip_from_msg() -> None:
    p = parse_rfc5424(_DOUBLE_WRAPPED_CMD)
    assert p is not None
    assert p["attacker_ip"] == "192.168.1.5"


def test_double_wrapped_bash_cmd_preserves_full_msg_body() -> None:
    p = parse_rfc5424(_DOUBLE_WRAPPED_CMD)
    assert p is not None
    # The cmd= value lives at the tail of msg; downstream consumers
    # (session aggregator, profiler) extract it from there.
    assert "cmd=ls /var/www/html" in p["msg"]


def test_single_wrapped_relay_line_still_parses_unchanged() -> None:
    """Regression guard: non-double-wrapped lines must keep their shape."""
    line = (
        "<134>1 2026-05-02T06:00:25.453826+00:00 omega-decky smtp - "
        "disconnect [relay@55555 src_ip=\"192.168.1.5\"]"
    )
    p = parse_rfc5424(line)
    assert p is not None
    assert p["event_type"] == "disconnect"
    assert p["decky"] == "omega-decky"
    assert p["service"] == "smtp"
    assert p["attacker_ip"] == "192.168.1.5"


def test_outer_msgid_set_does_not_recurse() -> None:
    """When outer MSGID is real, leave it alone — no inner-header lookup."""
    # Synthetic: outer MSGID=auth_attempt, body contains an
    # accidental inner-shaped substring. We must NOT replace
    # auth_attempt with anything from inside the body.
    line = (
        "<134>1 2026-05-02T06:22:48.089309+00:00 omega-decky auth-helper - "
        "auth_attempt [relay@55555 username=\"root\" src_ip=\"192.168.1.5\"]"
    )
    p = parse_rfc5424(line)
    assert p is not None
    assert p["event_type"] == "auth_attempt"
    assert p["decky"] == "omega-decky"
    assert p["service"] == "auth-helper"


def test_outer_nil_msgid_with_non_inner_body_unchanged() -> None:
    """NIL-MSGID lines whose body isn't a wrapped RFC5424 line stay NIL."""
    # The body is plain prose, not a `<TS> <HOST> <APP> <PROCID> <MSGID>` head.
    line = (
        "<14>1 2026-05-02T06:22:48.000000+00:00 host app - - - "
        "Failed password for root from 192.168.1.5 port 42772 ssh2"
    )
    p = parse_rfc5424(line)
    assert p is not None
    assert p["event_type"] == "-"
    assert p["attacker_ip"] == "192.168.1.5"
