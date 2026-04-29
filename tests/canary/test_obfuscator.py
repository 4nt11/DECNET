"""Tests for :mod:`decnet.canary.obfuscator` — the per-mint JS obfuscator.

Skipped when Node or the vendored ``javascript-obfuscator`` package is
not available (CI without npm install, fresh checkouts).  When the
toolchain is present we assert:

* determinism — same callback_token → byte-identical output
* per-mint uniqueness — different tokens → different output
* the rendered fingerprint embeds the mint UUID and beacon URL
  ahead of obfuscation, so the obfuscator's string-array transform
  can absorb them
* the output is non-empty and parses as JS via Node
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from decnet.canary import obfuscator


def _toolchain_ready() -> bool:
    if shutil.which(obfuscator._NODE_BIN) is None:  # noqa: SLF001
        return False
    helper_dir = Path(obfuscator._HELPER).parent  # noqa: SLF001
    return (helper_dir / "node_modules" / "javascript-obfuscator").is_dir()


pytestmark = pytest.mark.skipif(
    not _toolchain_ready(),
    reason="node + javascript-obfuscator not installed under decnet/canary",
)


def test_obfuscate_is_deterministic_per_token() -> None:
    src = "var x = 1; function hello() { return x + 2; } hello();"
    a = obfuscator.obfuscate(src, callback_token="aaaa-bbbb")
    b = obfuscator.obfuscate(src, callback_token="aaaa-bbbb")
    assert a == b
    assert a.strip()


def test_obfuscate_differs_across_tokens() -> None:
    src = "var x = 1; function hello() { return x + 2; } hello();"
    a = obfuscator.obfuscate(src, callback_token="aaaa-bbbb")
    b = obfuscator.obfuscate(src, callback_token="cccc-dddd")
    assert a != b


def test_render_fingerprint_js_substitutes_then_obfuscates() -> None:
    out = obfuscator.render_fingerprint_js(
        callback_token="tok-12345",
        http_base="https://canary.example.test",
        mint_uuid="11111111-2222-3333-4444-555555555555",
    )
    # Template placeholders must NOT survive into the output.
    assert "{{BEACON_URL}}" not in out
    assert "{{MINT_UUID}}" not in out
    assert out.strip()
    # Should be syntactically valid JS — Node parses it without throwing.
    proc = subprocess.run(
        [obfuscator._NODE_BIN, "--check", "-"],  # noqa: SLF001
        input=out, capture_output=True, text=True,
        timeout=15, check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_render_fingerprint_js_is_deterministic() -> None:
    kw = dict(
        callback_token="tok-12345",
        http_base="https://canary.example.test",
        mint_uuid="11111111-2222-3333-4444-555555555555",
    )
    a = obfuscator.render_fingerprint_js(**kw)
    b = obfuscator.render_fingerprint_js(**kw)
    assert a == b


def test_seed_from_token_is_31bit_positive() -> None:
    seed = obfuscator._seed_from_token("anything")  # noqa: SLF001
    assert 0 <= seed <= 0x7FFFFFFF


def test_config_from_seed_is_pure_function() -> None:
    cfg_a = obfuscator._config_from_seed(12345)  # noqa: SLF001
    cfg_b = obfuscator._config_from_seed(12345)  # noqa: SLF001
    assert cfg_a == cfg_b
    assert cfg_a["seed"] == 12345
    # Sanity: the stable knobs we never randomize are present.
    assert cfg_a["stringArray"] is True
    assert cfg_a["controlFlowFlattening"] is True


def test_obfuscator_error_on_bad_node_bin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(obfuscator, "_NODE_BIN", "/nonexistent/node-binary-xyz")
    with pytest.raises(obfuscator.ObfuscatorError):
        obfuscator.obfuscate("var x=1;", callback_token="t")
