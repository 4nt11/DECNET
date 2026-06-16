#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Emit an RFC 5424 `file_captured` line to stdout.

Called by capture.sh after a file drop has been mirrored into the quarantine
directory. Reads a single JSON object from stdin describing the event; emits
one syslog line that the collector parses into `logs.fields`.

The input JSON may contain arbitrary nested structures (writer cmdline,
concurrent_sessions, ss_snapshot). Bulky fields are base64-encoded into a
single `meta_json_b64` SD param — this avoids pathological characters
(`]`, `"`, `\\`) that the collector's SD-block regex cannot losslessly
round-trip when embedded directly.
"""

from __future__ import annotations

import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from syslog_bridge import syslog_line, write_syslog_file  # noqa: E402

# Flat fields ride as individual SD params (searchable, rendered as pills).
# Everything else is rolled into the base64 meta blob.
_FLAT_FIELDS: tuple[str, ...] = (
    "stored_as",
    "sha256",
    "size",
    "orig_path",
    "src_ip",
    "src_port",
    "ssh_user",
    "ssh_pid",
    "attribution",
    "writer_pid",
    "writer_comm",
    "writer_uid",
    "mtime",
)


def main() -> int:
    raw = sys.stdin.read()
    if not raw.strip():
        print("emit_capture: empty stdin", file=sys.stderr)
        return 1
    try:
        event: dict = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"emit_capture: bad JSON: {exc}", file=sys.stderr)
        return 1

    hostname = str(event.pop("_hostname", None) or os.environ.get("HOSTNAME") or "-")
    service = str(event.pop("_service", "ssh"))
    event_type = str(event.pop("_event_type", "file_captured"))

    fields: dict[str, str] = {}
    for key in _FLAT_FIELDS:
        if key in event:
            value = event.pop(key)
            if value is None or value == "":
                continue
            fields[key] = str(value)

    if event:
        payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False, sort_keys=True)
        fields["meta_json_b64"] = base64.b64encode(payload.encode("utf-8")).decode("ascii")

    line = syslog_line(
        service=service,
        hostname=hostname,
        event_type=event_type,
        **fields,
    )
    write_syslog_file(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
