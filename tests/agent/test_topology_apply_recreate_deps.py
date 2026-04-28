"""apply() must pass --always-recreate-deps to docker compose up.

Regression guard for the stale-netns-share bug: deckie service containers
join the base via ``network_mode: container:<base>`` and Docker binds the
share at service start. When compose recreates the base (e.g. ``ports:``
changed after toggling ``forwards_l3``) but decides services are
unchanged, the services keep a stale FD into the destroyed netns and
end up with only ``lo``. Forcing dependent recreation removes the race.

Found on first VPS deploy 2026-04-28: external SSH to the dmz-gateway
RST'd because the service's netns inode (37090) didn't match the base's
(41477). After ``compose down`` + ``up`` the inodes matched and traffic
flowed; this test guarantees agent re-applies do the same in one shot.
"""
from __future__ import annotations

import asyncio
import pathlib
from typing import Any

import pytest

from decnet.agent import topology_ops as _ops


class _FakeStore:
    def current(self) -> None:
        return None

    def put(self, *a: Any, **kw: Any) -> None:
        pass

    def clear(self, *a: Any, **kw: Any) -> None:
        pass


def test_apply_passes_always_recreate_deps_to_compose(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path,
) -> None:
    captured: list[tuple[str, ...]] = []

    def _fake_compose(*args: str, compose_file: pathlib.Path, **kw: Any) -> None:
        captured.append(args)

    monkeypatch.setattr(_ops, "_compose_with_retry", _fake_compose)
    monkeypatch.setattr(_ops, "create_bridge_network", lambda *a, **k: None)
    monkeypatch.setattr(_ops, "write_topology_compose", lambda *a, **k: None)
    monkeypatch.setattr(_ops, "_validate_topology", lambda *_: [])
    monkeypatch.setattr(_ops, "_validation_errors", lambda _: [])
    monkeypatch.setattr(_ops, "canonical_hash", lambda *_: "deadbeef")

    class _StubDockerClient:
        @staticmethod
        def from_env() -> "_StubDockerClient":
            return _StubDockerClient()

    monkeypatch.setattr(_ops, "docker", _StubDockerClient())

    hydrated = {
        "topology": {"id": "11111111-2222-3333-4444-555555555555"},
        "lans": [{"name": "dmz", "subnet": "10.0.0.0/24", "is_dmz": True}],
        "deckies": [],
        "edges": [],
    }

    asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
        _ops.apply(hydrated, "deadbeef", _FakeStore())
    )

    assert captured, "compose was never invoked"
    args = captured[-1]
    assert "up" in args, f"expected `up` in compose args, got {args}"
    assert "--always-recreate-deps" in args, (
        "agent must pass --always-recreate-deps so service containers' "
        "netns shares stay fresh when their base is recreated. Without "
        "this flag, services end up with stale FDs into destroyed "
        "namespaces and external traffic hits closed ports on the live "
        f"base. Got: {args}"
    )
