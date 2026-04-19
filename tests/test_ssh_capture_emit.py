"""
Round-trip tests for templates/ssh/emit_capture.py.

emit_capture reads a JSON event from stdin and writes one RFC 5424 line
to stdout. The collector's parse_rfc5424 must then recover the same
fields — flat ones as top-level SD params, bulky nested ones packed into
a single base64-encoded `meta_json_b64` SD param.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest

from decnet.collector.worker import parse_rfc5424

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "decnet" / "templates" / "ssh"
_EMIT_SCRIPT = _TEMPLATE_DIR / "emit_capture.py"


def _run_emit(event: dict) -> str:
    """Run emit_capture.py as a subprocess with `event` on stdin; return stdout."""
    result = subprocess.run(  # nosec B603 B607 — hardcoded args to test fixture
        [sys.executable, str(_EMIT_SCRIPT)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _baseline_event() -> dict:
    return {
        "_hostname": "test-decky-01",
        "_service": "ssh",
        "_event_type": "file_captured",
        "stored_as": "2026-04-18T02:22:56Z_abc123def456_payload.bin",
        "sha256": "deadbeef" * 8,
        "size": 4096,
        "orig_path": "/root/payload.bin",
        "src_ip": "198.51.100.7",
        "src_port": "55342",
        "ssh_user": "root",
        "ssh_pid": "1234",
        "attribution": "pid-chain",
        "writer_pid": "1234",
        "writer_comm": "scp",
        "writer_uid": "0",
        "mtime": "2026-04-18 02:22:56.000000000 +0000",
        "writer_cmdline": "scp -t /root/payload.bin",
        "writer_loginuid": "0",
        "concurrent_sessions": [
            {"user": "root", "tty": "pts/0", "login_at": "2026-04-18 02:22", "src_ip": "198.51.100.7"}
        ],
        "ss_snapshot": [
            {"pid": 1234, "src_ip": "198.51.100.7", "src_port": 55342}
        ],
    }


def test_emit_script_exists():
    assert _EMIT_SCRIPT.exists(), f"emit_capture.py missing: {_EMIT_SCRIPT}"


def test_emit_produces_parseable_rfc5424_line():
    line = _run_emit(_baseline_event())
    assert line.startswith("<"), f"expected <PRI>, got: {line[:20]!r}"
    parsed = parse_rfc5424(line)
    assert parsed is not None, f"collector could not parse: {line}"


def test_flat_fields_land_as_sd_params():
    event = _baseline_event()
    line = _run_emit(event)
    parsed = parse_rfc5424(line)
    assert parsed is not None
    fields = parsed["fields"]
    for key in ("stored_as", "sha256", "size", "orig_path", "src_ip",
                "ssh_user", "attribution", "writer_pid", "writer_comm"):
        assert fields.get(key) == str(event[key]), f"mismatch on {key}: {fields.get(key)!r} vs {event[key]!r}"


def test_event_type_and_service_propagate():
    line = _run_emit(_baseline_event())
    parsed = parse_rfc5424(line)
    assert parsed["service"] == "ssh"
    assert parsed["event_type"] == "file_captured"
    assert parsed["decky"] == "test-decky-01"
    # src_ip should populate attacker_ip via the collector's _IP_FIELDS lookup.
    assert parsed["attacker_ip"] == "198.51.100.7"


def test_meta_json_b64_roundtrips():
    event = _baseline_event()
    line = _run_emit(event)
    parsed = parse_rfc5424(line)
    b64 = parsed["fields"].get("meta_json_b64")
    assert b64, "meta_json_b64 missing from SD params"
    decoded = json.loads(base64.b64decode(b64).decode("utf-8"))
    assert decoded["writer_cmdline"] == event["writer_cmdline"]
    assert decoded["writer_loginuid"] == event["writer_loginuid"]
    assert decoded["concurrent_sessions"] == event["concurrent_sessions"]
    assert decoded["ss_snapshot"] == event["ss_snapshot"]


def test_meta_survives_awkward_characters():
    """Payload filenames and cmdlines can contain `]`, `"`, `\\` — all of
    which must round-trip via the base64 packing even though the raw SD
    format can't handle them."""
    event = _baseline_event()
    event["writer_cmdline"] = 'sh -c "echo ] \\"evil\\" > /tmp/x"'
    event["concurrent_sessions"] = [{"note": 'has ] and " and \\ chars'}]
    line = _run_emit(event)
    parsed = parse_rfc5424(line)
    assert parsed is not None
    b64 = parsed["fields"].get("meta_json_b64")
    decoded = json.loads(base64.b64decode(b64).decode("utf-8"))
    assert decoded["writer_cmdline"] == event["writer_cmdline"]
    assert decoded["concurrent_sessions"] == event["concurrent_sessions"]


def test_empty_stdin_exits_nonzero():
    result = subprocess.run(  # nosec B603 B607
        [sys.executable, str(_EMIT_SCRIPT)],
        input="",
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0


def test_no_sidecar_path_referenced():
    """emit_capture must never touch the filesystem — no meta.json, no
    CAPTURE_DIR writes. Proved by static source inspection."""
    src = _EMIT_SCRIPT.read_text()
    assert ".meta.json" not in src
    assert "open(" not in src  # stdin/stdout only
