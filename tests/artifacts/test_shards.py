"""Unit tests for ``decnet.artifacts.shards``.

The router-side wrapper is exercised by
``tests/api/transcripts/test_get_transcript.py``; this module pins
the pure-Python helpers directly so non-router callers (the
profiler worker, the collector) have a tested surface to lean on.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from decnet.artifacts import shards


_SID_A = "11111111-2222-3333-4444-555555555555"
_SID_B = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_DECKY = "test-decky"
_SERVICE = "ssh"
_SHARD_NAME = "sessions-2026-05-08.jsonl"


def _write_shard(root: Path, decky: str, service: str, name: str, lines: list[dict]) -> Path:
    shard_dir = root / decky / service / "transcripts"
    shard_dir.mkdir(parents=True, exist_ok=True)
    shard = shard_dir / name
    with shard.open("w") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")
    return shard


@pytest.fixture
def shard_root(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(shards, "ARTIFACTS_ROOT", tmp_path)
    shards._INDEX_CACHE.clear()
    return tmp_path


def test_validate_names_accepts_valid() -> None:
    shards.validate_names("test-decky", "ssh")
    shards.validate_names("d", "telnet")


def test_validate_names_rejects_bad_decky() -> None:
    with pytest.raises(ValueError, match="invalid decky"):
        shards.validate_names("Bad-Decky", "ssh")


def test_validate_names_rejects_bad_service() -> None:
    with pytest.raises(ValueError, match="invalid service"):
        shards.validate_names("d", "http")


def test_resolve_shard_happy_path(shard_root) -> None:
    p = shards.resolve_shard(_DECKY, _SERVICE, _SHARD_NAME)
    expected = (shard_root / _DECKY / _SERVICE / "transcripts" / _SHARD_NAME).resolve()
    assert p == expected


def test_resolve_shard_rejects_bad_shard_name(shard_root) -> None:
    with pytest.raises(ValueError, match="invalid shard name"):
        shards.resolve_shard(_DECKY, _SERVICE, "../etc/passwd")


def test_find_shard_with_sid_happy_path(shard_root) -> None:
    shard = _write_shard(
        shard_root, _DECKY, _SERVICE, _SHARD_NAME,
        [
            {"sid": _SID_A, "hdr": {}},
            {"sid": _SID_A, "t": 0.0, "ch": "i", "d": "x"},
            {"sid": _SID_B, "t": 0.0, "ch": "o", "d": "y"},
        ],
    )
    assert shards.find_shard_with_sid(_DECKY, _SERVICE, _SID_A) == shard
    assert shards.find_shard_with_sid(_DECKY, _SERVICE, _SID_B) == shard


def test_find_shard_with_sid_returns_none_when_sid_missing(shard_root) -> None:
    _write_shard(
        shard_root, _DECKY, _SERVICE, _SHARD_NAME,
        [{"sid": _SID_A, "hdr": {}}],
    )
    other = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"
    assert shards.find_shard_with_sid(_DECKY, _SERVICE, other) is None


def test_find_shard_with_sid_returns_none_when_dir_missing(shard_root) -> None:
    assert shards.find_shard_with_sid(_DECKY, _SERVICE, _SID_A) is None


def test_find_shard_with_sid_picks_newest_first(shard_root) -> None:
    """Two shards both contain the same sid (mid-night spans). Newest wins."""
    older = _write_shard(
        shard_root, _DECKY, _SERVICE, "sessions-2026-05-07.jsonl",
        [{"sid": _SID_A, "hdr": {}}],
    )
    newer = _write_shard(
        shard_root, _DECKY, _SERVICE, "sessions-2026-05-09.jsonl",
        [{"sid": _SID_A, "hdr": {}}],
    )
    found = shards.find_shard_with_sid(_DECKY, _SERVICE, _SID_A)
    assert found == newer
    assert found != older


def test_find_shard_with_sid_rejects_bad_decky(shard_root) -> None:
    with pytest.raises(ValueError):
        shards.find_shard_with_sid("Bad-Decky", _SERVICE, _SID_A)


def test_get_index_cache_hit_after_first_build(shard_root) -> None:
    shard = _write_shard(
        shard_root, _DECKY, _SERVICE, _SHARD_NAME,
        [{"sid": _SID_A, "hdr": {}}],
    )
    idx1, _ = shards.get_index(shard)
    idx2, _ = shards.get_index(shard)
    assert idx1 is idx2  # same cached object
