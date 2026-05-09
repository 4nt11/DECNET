"""Unit tests for ``decnet.profiler.behave_shell._handler``.

Direct exercise of ``handle_session_ended()`` without the worker loop
or a real bus. The handler is the load-bearing piece — bus / poll
fallback paths in the worker just feed it. Pin the contract here.
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

from decnet.profiler.behave_shell._handler import (
    _build_evidence_ref,
    handle_session_ended,
)


_SID = "11111111-2222-3333-4444-555555555555"
_DECKY = "test-decky"
_SERVICE = "ssh"
_IP = "10.0.0.5"
_ATTACKER_UUID = "att-uuid-abc"


def _write_shard(tmp_path, sid: str, lines: list[dict]) -> str:
    """Write a synthetic asciinema shard JSONL and return its path."""
    shard_dir = tmp_path / _DECKY / _SERVICE / "transcripts"
    shard_dir.mkdir(parents=True, exist_ok=True)
    shard = shard_dir / "sessions-2026-05-08.jsonl"
    with shard.open("w") as f:
        for line in lines:
            f.write(json.dumps(line) + "\n")
    return str(shard)


def _shard_with_typing_session(tmp_path, sid: str = _SID) -> str:
    """A minimal session with enough events to fire the calibration floor."""
    lines = [{"sid": sid, "hdr": {"version": 2, "width": 80, "height": 24,
                                  "timestamp": 1714521600}}]
    text = "ls\rps\rid\rwhoami\rpwd\runame\r"
    for i, c in enumerate(text):
        lines.append({"sid": sid, "t": i * 0.05, "ch": "i", "d": c})
    lines.append({"sid": sid, "t": 5.0, "ch": "o", "d": "anti@host:~$ "})
    return _write_shard(tmp_path, sid, lines)


def _payload(shard_path: str | None) -> dict[str, Any]:
    return {
        "session_id": _SID,
        "attacker_uuid": None,
        "attacker_ip": _IP,
        "decky_id": _DECKY,
        "service": _SERVICE,
        "ended_at": "2026-05-08T10:00:00",
        "duration_s": 5.0,
        "commands": [],
        "shard_path": shard_path,
    }


def _make_repo(*, has_evidence: bool = False, attacker_uuid: str | None = _ATTACKER_UUID):
    repo = AsyncMock()
    repo.has_observations_for_evidence = AsyncMock(return_value=has_evidence)
    repo.get_attacker_uuid_by_ip = AsyncMock(return_value=attacker_uuid)
    repo.upsert_observation = AsyncMock(return_value="row-uuid")
    return repo


def test_evidence_ref_shape() -> None:
    ref = _build_evidence_ref(
        "deck", "ssh", "/var/lib/decnet/artifacts/deck/ssh/transcripts/sessions-2026-05-08.jsonl",
        "abc",
    )
    assert ref == "shard:deck/ssh/sessions-2026-05-08.jsonl#abc"


async def test_happy_path_persists_and_publishes(tmp_path) -> None:
    shard_path = _shard_with_typing_session(tmp_path)
    repo = _make_repo()
    published: list[tuple[str, dict[str, Any], str]] = []
    publish = lambda topic, payload, etype: published.append((topic, payload, etype))

    n = await handle_session_ended(repo, _payload(shard_path), publish)

    assert n > 0
    assert repo.upsert_observation.await_count == n
    # Every persistence row must include the attacker_uuid denorm.
    for call in repo.upsert_observation.await_args_list:
        row = call.args[0]
        assert row["attacker_uuid"] == _ATTACKER_UUID
        assert row["evidence_ref"].startswith("shard:")
    # Bus published once per observation.
    assert len(published) == n
    for topic, payload, etype in published:
        assert topic.startswith("attacker.observation.")
        # Adapter excludes id/ts/v from payload body; handler re-merges.
        assert "id" in payload and "ts" in payload and "v" in payload
        # Phase 5 amendment: attacker_uuid is also re-merged so the
        # per-attacker SSE route can filter in O(1).
        assert payload["attacker_uuid"] == _ATTACKER_UUID


async def test_missing_session_id_skipped(tmp_path) -> None:
    shard_path = _shard_with_typing_session(tmp_path)
    p = _payload(shard_path)
    p["session_id"] = None
    repo = _make_repo()
    n = await handle_session_ended(repo, p, None)
    assert n == 0
    repo.upsert_observation.assert_not_awaited()


async def test_missing_shard_path_skipped(tmp_path) -> None:
    repo = _make_repo()
    n = await handle_session_ended(repo, _payload(None), None)
    assert n == 0
    repo.has_observations_for_evidence.assert_not_awaited()


async def test_already_profiled_skipped(tmp_path) -> None:
    """Idempotency: handler returns 0 if has_observations_for_evidence True."""
    shard_path = _shard_with_typing_session(tmp_path)
    repo = _make_repo(has_evidence=True)
    n = await handle_session_ended(repo, _payload(shard_path), None)
    assert n == 0
    repo.get_attacker_uuid_by_ip.assert_not_awaited()
    repo.upsert_observation.assert_not_awaited()


async def test_attacker_uuid_unresolved_defers(tmp_path) -> None:
    """Cold IP — no Attacker row yet. Skip and let the next tick retry."""
    shard_path = _shard_with_typing_session(tmp_path)
    repo = _make_repo(attacker_uuid=None)
    n = await handle_session_ended(repo, _payload(shard_path), None)
    assert n == 0
    repo.upsert_observation.assert_not_awaited()


async def test_shard_missing_on_disk_defers(tmp_path) -> None:
    """shard_path points at a file that hasn't been flushed yet."""
    fake_path = str(tmp_path / "nope" / "sessions-2026-05-08.jsonl")
    repo = _make_repo()
    n = await handle_session_ended(repo, _payload(fake_path), None)
    assert n == 0
    repo.upsert_observation.assert_not_awaited()


async def test_sid_not_in_shard_skipped(tmp_path) -> None:
    """Shard exists but doesn't contain our sid."""
    other_sid = "ffffffff-eeee-dddd-cccc-bbbbbbbbbbbb"
    shard_path = _shard_with_typing_session(tmp_path, sid=other_sid)
    repo = _make_repo()
    n = await handle_session_ended(repo, _payload(shard_path), None)
    assert n == 0
    repo.upsert_observation.assert_not_awaited()


async def test_publish_failure_does_not_raise(tmp_path) -> None:
    """Bus publish failures are best-effort; persistence already
    succeeded so we don't roll back."""
    shard_path = _shard_with_typing_session(tmp_path)
    repo = _make_repo()

    def _bad(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("bus exploded")

    n = await handle_session_ended(repo, _payload(shard_path), _bad)
    assert n > 0
    assert repo.upsert_observation.await_count == n


async def test_publish_none_is_silent(tmp_path) -> None:
    """publish=None is the no-op path used in poll-fallback mode."""
    shard_path = _shard_with_typing_session(tmp_path)
    repo = _make_repo()
    n = await handle_session_ended(repo, _payload(shard_path), None)
    assert n > 0


async def test_attacker_uuid_in_payload_for_filter(tmp_path) -> None:
    """Phase 5 amendment: every published observation carries the
    DECNET-side ``attacker_uuid`` denorm (NOT the BEHAVE
    ``identity_ref``, which stays None until attribution exists)."""
    shard_path = _shard_with_typing_session(tmp_path)
    repo = _make_repo()
    published: list[tuple[str, dict[str, Any], str]] = []
    publish = lambda topic, payload, etype: published.append((topic, payload, etype))

    n = await handle_session_ended(repo, _payload(shard_path), publish)

    assert n > 0
    for _topic, payload, _etype in published:
        assert payload["attacker_uuid"] == _ATTACKER_UUID
        # identity_ref ride-along comes from the BEHAVE adapter's
        # to_event_payload — None today, that's fine. The point is the
        # attacker_uuid is INDEPENDENT of identity_ref.
        assert payload.get("identity_ref") is None
