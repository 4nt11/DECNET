# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Stealth-hardening assertions for the SSH honeypot template.

The three capture artifacts — syslog_bridge.py, emit_capture.py, capture.sh —
used to land as plaintext files in the container (world-readable by the
attacker, who is root in-container). They are now packed into /entrypoint.sh
as XOR+gzip+base64 blobs at image-build time by _build_stealth.py.

These tests pin the stealth contract at the source-template level so
regressions surface without needing a docker build.
"""

from __future__ import annotations

import base64
import gzip
import importlib.util
import sys
from pathlib import Path

from decnet.services.registry import get_service


def _ctx() -> Path:
    return get_service("ssh").dockerfile_context()


def _load_build_stealth():
    path = _ctx() / "_build_stealth.py"
    spec = importlib.util.spec_from_file_location("_build_stealth", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Build helper exists and is wired into the Dockerfile
# ---------------------------------------------------------------------------

def test_build_stealth_helper_shipped():
    helper = _ctx() / "_build_stealth.py"
    assert helper.exists(), "_build_stealth.py missing from SSH template"
    body = helper.read_text()
    assert "__STEALTH_KEY__" in body
    assert "__EMIT_CAPTURE_B64__" in body
    assert "__JOURNAL_RELAY_B64__" in body


def test_dockerfile_invokes_build_stealth():
    df = (_ctx() / "Dockerfile").read_text()
    assert "_build_stealth.py" in df
    assert "python3 /tmp/build/_build_stealth.py" in df


# ---------------------------------------------------------------------------
# Entrypoint template shape
# ---------------------------------------------------------------------------

def test_entrypoint_is_template_with_placeholders():
    ep = (_ctx() / "entrypoint.sh").read_text()
    # Pre-build template — placeholders must be present; the Docker build
    # stage substitutes them.
    assert "__STEALTH_KEY__" in ep
    assert "__EMIT_CAPTURE_B64__" in ep
    assert "__JOURNAL_RELAY_B64__" in ep


def test_entrypoint_decodes_via_xor():
    ep = (_ctx() / "entrypoint.sh").read_text()
    # XOR-then-gunzip layering: base64 -> xor -> gunzip
    assert "base64 -d" in ep
    assert "gunzip" in ep
    # The decoded vars drive the capture loop.
    assert "EMIT_CAPTURE_PY" in ep
    assert "export EMIT_CAPTURE_PY" in ep


def test_entrypoint_no_plaintext_python_path():
    ep = (_ctx() / "entrypoint.sh").read_text()
    assert "/opt/emit_capture.py" not in ep
    assert "/opt/syslog_bridge.py" not in ep
    assert "/usr/libexec/udev/journal-relay" not in ep


# ---------------------------------------------------------------------------
# End-to-end: pack + round-trip
# ---------------------------------------------------------------------------

def test_build_stealth_merge_and_pack_roundtrip(tmp_path, monkeypatch):
    """Merge the real sources, pack them, and decode — assert semantic equality."""
    mod = _load_build_stealth()

    build = tmp_path / "build"
    build.mkdir()
    ctx = _ctx()
    for name in ("syslog_bridge.py", "emit_capture.py", "capture.sh", "entrypoint.sh"):
        (build / name).write_text((ctx / name).read_text())

    monkeypatch.setattr(mod, "BUILD", build)
    out_dir = tmp_path / "out"
    out_dir.mkdir()

    # Redirect the write target so we don't touch /entrypoint.sh.
    import pathlib
    real_path = pathlib.Path
    def fake_path(arg, *a, **kw):
        if arg == "/entrypoint.sh":
            return real_path(out_dir) / "entrypoint.sh"
        return real_path(arg, *a, **kw)
    monkeypatch.setattr(mod, "Path", fake_path)

    rc = mod.main()
    assert rc == 0

    rendered = (out_dir / "entrypoint.sh").read_text()
    for marker in ("__STEALTH_KEY__", "__EMIT_CAPTURE_B64__", "__JOURNAL_RELAY_B64__"):
        assert marker not in rendered, f"{marker} left in rendered entrypoint"

    # Extract key + blobs and decode.
    import re
    key = int(re.search(r"_STEALTH_KEY=(\d+)", rendered).group(1))
    emit_b64 = re.search(r"_EMIT_CAPTURE_B64='([^']+)'", rendered).group(1)
    relay_b64 = re.search(r"_JOURNAL_RELAY_B64='([^']+)'", rendered).group(1)

    def unpack(s: str) -> str:
        xored = base64.b64decode(s)
        gz = bytes(b ^ key for b in xored)
        return gzip.decompress(gz).decode("utf-8")

    emit_src = unpack(emit_b64)
    relay_src = unpack(relay_b64)

    # Merged python must contain both module bodies, with the import hack stripped.
    assert "def syslog_line(" in emit_src
    assert "def main() -> int:" in emit_src
    assert "from syslog_bridge import" not in emit_src
    assert "sys.path.insert" not in emit_src

    # Capture loop must reference the in-memory python var, not the old path.
    assert "EMIT_CAPTURE_PY" in relay_src
    assert "/opt/emit_capture.py" not in relay_src
    assert "inotifywait" in relay_src or "INOTIFY_BIN" in relay_src
