# SPDX-License-Identifier: AGPL-3.0-or-later
"""TTP worker resolves ``attacker_uuid`` from ``attacker_ip`` per repo lookup.

The collector publishes ``attacker.session.ended`` with
``attacker_uuid: null`` because it doesn't talk to the DB.
:class:`TTPTag` rejects rows whose ``attacker_uuid`` AND
``identity_uuid`` are both NULL — so the worker must resolve via
:meth:`BaseRepository.get_attacker_uuid_by_ip` before fanning the
event out, and drop the event entirely when no anchor can be set.
"""
from __future__ import annotations

from typing import Any

import pytest

from decnet.ttp.worker import _resolve_attacker_uuid


class _FakeRepo:
    def __init__(self, mapping: dict[str, str | None]) -> None:
        self._mapping = mapping
        self.calls: list[str] = []

    async def get_attacker_uuid_by_ip(self, ip: str) -> str | None:
        self.calls.append(ip)
        return self._mapping.get(ip)


@pytest.mark.asyncio
async def test_payload_with_attacker_uuid_is_returned_unchanged() -> None:
    repo = _FakeRepo({})
    payload = {"attacker_uuid": "att-1", "attacker_ip": "1.2.3.4"}
    out = await _resolve_attacker_uuid(repo, payload)  # type: ignore[arg-type]
    assert out is payload  # short-circuit, no DB lookup
    assert repo.calls == []


@pytest.mark.asyncio
async def test_payload_with_identity_uuid_is_returned_unchanged() -> None:
    repo = _FakeRepo({})
    payload = {"identity_uuid": "id-1", "attacker_ip": "1.2.3.4"}
    out = await _resolve_attacker_uuid(repo, payload)  # type: ignore[arg-type]
    assert out is payload
    assert repo.calls == []


@pytest.mark.asyncio
async def test_payload_resolves_uuid_via_attacker_ip() -> None:
    repo = _FakeRepo({"192.168.1.5": "att-7"})
    payload: dict[str, Any] = {
        "attacker_ip": "192.168.1.5",
        "session_id": "sess-1",
        "commands": [{"command_text": "whoami"}],
    }
    out = await _resolve_attacker_uuid(repo, payload)  # type: ignore[arg-type]
    assert out is not None
    assert out["attacker_uuid"] == "att-7"
    assert out["attacker_ip"] == "192.168.1.5"
    # Other fields preserved.
    assert out["session_id"] == "sess-1"
    assert repo.calls == ["192.168.1.5"]


@pytest.mark.asyncio
async def test_payload_dropped_when_ip_unknown_to_repo() -> None:
    """Profiler hasn't seen this IP yet → no Attacker row → drop."""
    repo = _FakeRepo({})
    payload = {"attacker_ip": "10.0.0.99"}
    out = await _resolve_attacker_uuid(repo, payload)  # type: ignore[arg-type]
    assert out is None


@pytest.mark.asyncio
async def test_payload_dropped_when_no_anchor_fields_present() -> None:
    repo = _FakeRepo({})
    payload: dict[str, Any] = {"foo": "bar"}
    out = await _resolve_attacker_uuid(repo, payload)  # type: ignore[arg-type]
    assert out is None
    assert repo.calls == []


@pytest.mark.asyncio
async def test_payload_dropped_when_attacker_ip_is_unknown_sentinel() -> None:
    repo = _FakeRepo({"Unknown": "should-not-resolve"})
    payload = {"attacker_ip": "Unknown"}
    out = await _resolve_attacker_uuid(repo, payload)  # type: ignore[arg-type]
    assert out is None
    # We must not even ask the repo about the literal "Unknown" sentinel.
    assert repo.calls == []


@pytest.mark.asyncio
async def test_payload_dropped_when_repo_lookup_raises() -> None:
    class _RaisingRepo:
        async def get_attacker_uuid_by_ip(self, _ip: str) -> str | None:
            raise RuntimeError("db gone")

    out = await _resolve_attacker_uuid(
        _RaisingRepo(),  # type: ignore[arg-type]
        {"attacker_ip": "1.2.3.4"},
    )
    assert out is None
