"""
RFC 5424 log line parser for the DECNET correlation engine.

Parses log lines produced by decnet service containers and extracts
the fields needed for cross-decky correlation: attacker IP, decky name,
service, event type, and timestamp.

Log format (produced by decnet.logging.syslog_formatter):
  <PRI>1 TIMESTAMP HOSTNAME APP-NAME - MSGID [relay@55555 k1="v1" k2="v2"] [MSG]

The attacker IP may appear under several field names depending on service:
  src_ip  — ftp, smtp, http, most services
  src     — mssql (legacy)
  client_ip, remote_ip, ip  — future / third-party services
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

# RFC 5424 line structure
_RFC5424_RE = re.compile(
    r"^<\d+>1 "
    r"(\S+) "       # 1: TIMESTAMP
    r"(\S+) "       # 2: HOSTNAME (decky name)
    r"(\S+) "       # 3: APP-NAME (service)
    r"- "           # PROCID always NILVALUE
    r"(\S+) "       # 4: MSGID (event_type)
    r"(.+)$",       # 5: SD element + optional MSG
)

# Honeypot SSH PROMPT_COMMAND lines arrive double-wrapped: the
# Docker-stdout collector envelope wraps the inner ``logger
# --rfc5424 --msgid command -t bash …`` line. Outer MSGID is NIL,
# real MSGID lives in the body. Mirrors the unwrap logic in
# ``decnet.collector.worker._INNER_RFC5424_RE`` — the two parsers
# read the same on-wire format.
_INNER_RFC5424_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\S+)\s+"  # 1: inner TIMESTAMP
    r"(\S+)\s+"                       # 2: inner HOSTNAME
    r"(\S+)\s+"                       # 3: inner APP-NAME
    r"\S+\s+"                         # PROCID (NIL or PID)
    r"(\S+)\s+"                       # 4: inner MSGID
    r"(.+)$",                         # 5: inner SD/MSG remainder
)

# Structured data block: [relay@55555 k="v" ...]
_SD_BLOCK_RE = re.compile(r'\[relay@55555\s+(.*?)\]', re.DOTALL)

# Individual param: key="value" (with escaped chars inside value)
_PARAM_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

# Field names to probe for attacker IP, in priority order
_IP_FIELDS = ("src_ip", "src", "client_ip", "remote_ip", "remote_addr", "target_ip", "ip")

# Native syslog producers (sshd, pam_unix routed through rsyslog) emit
# free prose with no SD block. Pull the remote address out of idiomatic
# anchors first ("from <ip>", "rhost=<ip>"), then fall back to the first
# IPv4 in the line. Anchored matches keep us from picking the local
# listener in "Connection from X port Y on Z port 22".
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_IPV6 = r"[0-9a-fA-F:]+:[0-9a-fA-F:]+"
_IP_RE = rf"(?:{_IPV4}|{_IPV6})"
_MSG_IP_ANCHORED_RE = re.compile(
    rf"\b(?:from|rhost[:=]|client[:=]|src[:=])\s*({_IP_RE})",
    re.IGNORECASE,
)
_MSG_IP_BARE_RE = re.compile(rf"\b({_IPV4})\b")


EventKind = Literal["attacker", "mutation"]


@dataclass
class LogEvent:
    """A single parsed event from a DECNET syslog line."""

    timestamp: datetime
    decky: str          # HOSTNAME field — the decky node name
    service: str        # APP-NAME — which honeypot service
    event_type: str     # MSGID — what happened (connection, login_attempt, …)
    attacker_ip: str | None  # extracted from SD params; None if not present
    fields: dict[str, str]   # all structured data params
    raw: str            # original log line (stripped)
    # ``attacker`` = service-emitted event keyed on a source IP (the
    # existing correlation input).  ``mutation`` = ``mutator`` worker
    # event — same RFC 5424 wire format but routed into a separate
    # per-decky index so substrate transitions can be interleaved into
    # attacker traversals without polluting the per-IP event stream.
    kind: EventKind = field(default="attacker")


def _parse_sd_params(sd_rest: str) -> dict[str, str]:
    """Extract key=value pairs from the SD element portion of a log line."""
    block = _SD_BLOCK_RE.search(sd_rest)
    if not block:
        return {}
    params: dict[str, str] = {}
    for key, val in _PARAM_RE.findall(block.group(1)):
        # Unescape RFC 5424 SD-PARAM-VALUE escapes
        params[key] = val.replace('\\"', '"').replace("\\\\", "\\").replace("\\]", "]")
    return params


def _extract_attacker_ip(fields: dict[str, str], msg: str = "") -> str | None:
    for fname in _IP_FIELDS:
        if fname in fields:
            return fields[fname]
    if msg:
        anchored = _MSG_IP_ANCHORED_RE.search(msg)
        if anchored:
            return anchored.group(1)
        bare = _MSG_IP_BARE_RE.search(msg)
        if bare:
            return bare.group(1)
    return None


def parse_line(line: str) -> LogEvent | None:
    """
    Parse a single RFC 5424 DECNET syslog line into a LogEvent.

    Returns None for blank lines, non-DECNET lines, or lines missing
    the required RFC 5424 header fields.
    """
    line = line.strip()
    if not line:
        return None

    m = _RFC5424_RE.match(line)
    if not m:
        return None

    ts_raw, decky, service, event_type, sd_rest = m.groups()

    # Unwrap double-wrapped Docker-stdout envelopes around bash
    # PROMPT_COMMAND lines. See ``_INNER_RFC5424_RE`` and the matching
    # logic in ``decnet.collector.worker.parse_rfc5424``. Must run
    # before the decky/service NIL-guard below — the OUTER decky is
    # the docker host, the inner header carries the real source.
    if event_type == "-" and sd_rest.startswith("-"):
        body = sd_rest[1:].lstrip()
        inner = _INNER_RFC5424_RE.match(body)
        if inner is not None:
            _i_ts, i_host, i_app, i_msgid, i_rest = inner.groups()
            decky = i_host
            service = i_app
            event_type = i_msgid
            sd_rest = i_rest

    if decky == "-" or service == "-":
        return None

    try:
        timestamp = datetime.fromisoformat(ts_raw)
    except ValueError:
        return None

    fields = _parse_sd_params(sd_rest)
    if sd_rest.startswith("-"):
        msg = sd_rest[1:].lstrip()
    else:
        tail = re.search(r'\]\s+(.+)$', sd_rest)
        msg = tail.group(1).strip() if tail else ""
    attacker_ip = _extract_attacker_ip(fields, msg)

    # Free-form bash PROMPT_COMMAND lines arrive with MSGID=NIL or MSGID=command
    # and a body like `CMD uid=0 user=root src=… pwd=… cmd=<rest of line>`.
    # Without this rewrite they're invisible to the behavioral profiler, which
    # filters on event_type ∈ {command, exec, query, …}. The Dockerfile logger
    # invocation uses --msgid command, so we must also handle the non-nil case.
    if event_type in ("-", "command") and msg.startswith("CMD ") and "command" not in fields:
        event_type = "command"
        head, sep, cmd_rest = msg[4:].partition("cmd=")
        for k, v in re.findall(r'(\w+)=(\S+)', head):
            fields.setdefault(k, v)
        if sep:
            fields.setdefault("command", cmd_rest)

    # Mutator-emitted transitions arrive on the same ingest stream but
    # belong in the substrate-state index, not the per-IP attacker one.
    kind: EventKind = (
        "mutation"
        if service == "mutator" and event_type == "decky_mutated"
        else "attacker"
    )

    return LogEvent(
        timestamp=timestamp,
        decky=decky,
        service=service,
        event_type=event_type,
        attacker_ip=attacker_ip,
        fields=fields,
        raw=line,
        kind=kind,
    )
