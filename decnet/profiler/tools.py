"""Tool attribution for DECNET attacker profiles.

Two detection paths:

  * `guess_tools()` — matches beacon cadence (mean IAT + CV jitter) against
    known C2 default profiles (Cobalt Strike, Sliver, Havoc, Mythic).
  * `detect_tools_from_headers()` — scans HTTP `request` events for
    tool-identifying User-Agent / X-Mailer / etc. headers (Nmap NSE, sqlmap,
    nuclei, masscan, metasploit, curl, and friends).
"""

from __future__ import annotations

import json
import re
from typing import Any

from decnet.correlation.parser import LogEvent
from decnet.telemetry import traced as _traced

# ─── C2 tool attribution signatures (beacon timing) ─────────────────────────
#
# Each entry lists the default beacon cadence profile of a popular C2.
# A profile *matches* an attacker when:
#   - mean inter-event time is within ±`interval_tolerance` seconds, AND
#   - jitter (cv = stdev / mean) is within ±`jitter_tolerance`
#
# Multiple matches are all returned (attacker may run multiple implants).

_TOOL_SIGNATURES: tuple[dict[str, Any], ...] = (
    {
        "name": "cobalt_strike",
        "interval_s": 60.0,
        "interval_tolerance_s": 8.0,
        "jitter_cv": 0.20,
        "jitter_tolerance": 0.05,
    },
    {
        "name": "sliver",
        "interval_s": 60.0,
        "interval_tolerance_s": 10.0,
        "jitter_cv": 0.30,
        "jitter_tolerance": 0.08,
    },
    {
        "name": "havoc",
        "interval_s": 45.0,
        "interval_tolerance_s": 8.0,
        "jitter_cv": 0.10,
        "jitter_tolerance": 0.03,
    },
    {
        "name": "mythic",
        "interval_s": 30.0,
        "interval_tolerance_s": 6.0,
        "jitter_cv": 0.15,
        "jitter_tolerance": 0.03,
    },
)

# ─── Header-based tool signatures ───────────────────────────────────────────
#
# Scanned against HTTP `request` events.  `pattern` is a case-insensitive
# substring (or a regex anchored with ^ if it starts with that character).
# `header` is matched case-insensitively against the event's headers dict.

_HEADER_TOOL_SIGNATURES: tuple[dict[str, str], ...] = (
    {"name": "nmap",             "header": "user-agent", "pattern": "Nmap Scripting Engine"},
    {"name": "gophish",          "header": "x-mailer",   "pattern": "gophish"},
    {"name": "nikto",            "header": "user-agent", "pattern": "Nikto"},
    {"name": "sqlmap",           "header": "user-agent", "pattern": "sqlmap"},
    {"name": "nuclei",           "header": "user-agent", "pattern": "Nuclei"},
    {"name": "masscan",          "header": "user-agent", "pattern": "masscan"},
    {"name": "zgrab",            "header": "user-agent", "pattern": "zgrab"},
    {"name": "metasploit",       "header": "user-agent", "pattern": "Metasploit"},
    {"name": "curl",             "header": "user-agent", "pattern": "^curl/"},
    {"name": "python_requests",  "header": "user-agent", "pattern": "python-requests"},
    {"name": "gobuster",         "header": "user-agent", "pattern": "gobuster"},
    {"name": "dirbuster",        "header": "user-agent", "pattern": "DirBuster"},
    {"name": "hydra",            "header": "user-agent", "pattern": "hydra"},
    {"name": "wfuzz",            "header": "user-agent", "pattern": "Wfuzz"},
)


def guess_tools(mean_iat_s: float | None, cv: float | None) -> list[str]:
    """
    Match (mean_iat, cv) against known C2 default beacon profiles.

    Returns a list of all matching tool names (may be empty).  Multiple
    matches are all returned because an attacker can run several implants.
    """
    if mean_iat_s is None or cv is None:
        return []

    hits: list[str] = []
    for sig in _TOOL_SIGNATURES:
        if abs(mean_iat_s - sig["interval_s"]) > sig["interval_tolerance_s"]:
            continue
        if abs(cv - sig["jitter_cv"]) > sig["jitter_tolerance"]:
            continue
        hits.append(sig["name"])

    return hits


# Keep the old name as an alias so callers that expected a single string still
# compile, but mark it deprecated.  Returns the first hit or None.
def guess_tool(mean_iat_s: float | None, cv: float | None) -> str | None:
    """Deprecated: use guess_tools() instead."""
    hits = guess_tools(mean_iat_s, cv)
    if len(hits) == 1:
        return hits[0]
    return None


@_traced("profiler.detect_tools_from_headers")
def detect_tools_from_headers(events: list[LogEvent]) -> list[str]:
    """
    Scan HTTP `request` events for tool-identifying headers.

    Checks User-Agent, X-Mailer, and other headers case-insensitively
    against `_HEADER_TOOL_SIGNATURES`.  Returns a deduplicated list of
    matched tool names in detection order.
    """
    found: list[str] = []
    seen: set[str] = set()

    for e in events:
        if e.event_type != "request":
            continue

        raw_headers = e.fields.get("headers")
        if not raw_headers:
            continue

        # headers may arrive as a JSON string, a Python-repr string (legacy),
        # or a dict already (in-memory / test paths).
        if isinstance(raw_headers, str):
            try:
                headers: dict[str, str] = json.loads(raw_headers)
            except (json.JSONDecodeError, ValueError):
                # Backward-compat: events written before the JSON-encode fix
                # were serialized as Python repr via str(dict).  ast.literal_eval
                # handles that safely (no arbitrary code execution).
                try:
                    import ast as _ast
                    _parsed = _ast.literal_eval(raw_headers)
                    if isinstance(_parsed, dict):
                        headers = _parsed
                    else:
                        continue
                except Exception:  # nosec B112 — skip unparseable header values
                    continue
        elif isinstance(raw_headers, dict):
            headers = raw_headers
        else:
            continue

        # Normalise header keys to lowercase for matching.
        lc_headers: dict[str, str] = {k.lower(): str(v) for k, v in headers.items()}

        for sig in _HEADER_TOOL_SIGNATURES:
            name = sig["name"]
            if name in seen:
                continue
            value = lc_headers.get(sig["header"])
            if value is None:
                continue
            pattern = sig["pattern"]
            if pattern.startswith("^"):
                if re.match(pattern, value, re.IGNORECASE):
                    found.append(name)
                    seen.add(name)
            else:
                if pattern.lower() in value.lower():
                    found.append(name)
                    seen.add(name)

    return found
