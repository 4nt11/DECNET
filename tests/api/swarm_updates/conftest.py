# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared fixtures for /api/v1/swarm-updates tests.

The tests never talk to a real worker — ``UpdaterClient`` is monkeypatched
to a recording fake. That keeps the tests fast and lets us assert call
shapes (tarball-once, per-host dispatch, include_self ordering) without
standing up TLS endpoints.
"""
from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

from decnet.web.dependencies import repo


async def _add_host(
    name: str,
    address: str = "10.0.0.1",
    *,
    with_updater: bool = True,
    status: str = "enrolled",
) -> dict[str, Any]:
    uuid = str(_uuid.uuid4())
    await repo.add_swarm_host({
        "uuid": uuid,
        "name": name,
        "address": address,
        "agent_port": 8765,
        "status": status,
        "client_cert_fingerprint": "abc123",
        "updater_cert_fingerprint": "def456" if with_updater else None,
        "cert_bundle_path": f"/tmp/{name}",
        "enrolled_at": datetime.now(timezone.utc),
        "notes": None,
    })
    return {"uuid": uuid, "name": name, "address": address}


@pytest.fixture
def add_host():
    return _add_host


@pytest.fixture
def fake_updater(monkeypatch):
    """Install a fake ``UpdaterClient`` + tar builder into every route module.

    The returned ``Fake`` exposes hooks so individual tests decide per-host
    behaviour: response codes, exceptions, update-self outcomes, etc.
    """

    class FakeResponse:
        def __init__(self, status_code: int, body: dict[str, Any] | None = None):
            self.status_code = status_code
            self._body = body or {}
            self.content = b"payload"

        def json(self) -> dict[str, Any]:
            return self._body

    class FakeUpdaterClient:
        calls: list[tuple[str, str, dict]] = []  # (host_name, method, kwargs)
        health_responses: dict[str, dict[str, Any]] = {}
        update_responses: dict[str, FakeResponse | BaseException] = {}
        update_self_responses: dict[str, FakeResponse | BaseException] = {}
        rollback_responses: dict[str, FakeResponse | BaseException] = {}

        def __init__(self, host=None, **_kw):
            self._name = host["name"] if host else "?"

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def health(self):
            FakeUpdaterClient.calls.append((self._name, "health", {}))
            resp = FakeUpdaterClient.health_responses.get(self._name)
            if isinstance(resp, BaseException):
                raise resp
            return resp or {"status": "ok", "releases": []}

        async def update(self, tarball, sha=""):
            FakeUpdaterClient.calls.append((self._name, "update", {"tarball": tarball, "sha": sha}))
            resp = FakeUpdaterClient.update_responses.get(self._name, FakeResponse(200, {"probe": "ok"}))
            if isinstance(resp, BaseException):
                raise resp
            return resp

        async def update_self(self, tarball, sha=""):
            FakeUpdaterClient.calls.append((self._name, "update_self", {"tarball": tarball, "sha": sha}))
            resp = FakeUpdaterClient.update_self_responses.get(self._name, FakeResponse(200))
            if isinstance(resp, BaseException):
                raise resp
            return resp

        async def rollback(self):
            FakeUpdaterClient.calls.append((self._name, "rollback", {}))
            resp = FakeUpdaterClient.rollback_responses.get(self._name, FakeResponse(200, {"status": "rolled back"}))
            if isinstance(resp, BaseException):
                raise resp
            return resp

    # Reset class-level state each test — fixtures are function-scoped but
    # the class dicts survive otherwise.
    FakeUpdaterClient.calls = []
    FakeUpdaterClient.health_responses = {}
    FakeUpdaterClient.update_responses = {}
    FakeUpdaterClient.update_self_responses = {}
    FakeUpdaterClient.rollback_responses = {}

    for mod in (
        "decnet.web.router.swarm_updates.api_list_host_releases",
        "decnet.web.router.swarm_updates.api_push_update",
        "decnet.web.router.swarm_updates.api_push_update_self",
        "decnet.web.router.swarm_updates.api_rollback_host",
    ):
        monkeypatch.setattr(f"{mod}.UpdaterClient", FakeUpdaterClient)

    # Stub the tarball builders so tests don't spend seconds re-tarring the
    # repo on every assertion. The byte contents don't matter for the route
    # contract — the updater side is faked.
    monkeypatch.setattr(
        "decnet.web.router.swarm_updates.api_push_update.tar_working_tree",
        lambda root, extra_excludes=None: b"tarball-bytes",
    )
    monkeypatch.setattr(
        "decnet.web.router.swarm_updates.api_push_update.detect_git_sha",
        lambda root: "deadbeef",
    )
    monkeypatch.setattr(
        "decnet.web.router.swarm_updates.api_push_update_self.tar_working_tree",
        lambda root, extra_excludes=None: b"tarball-bytes",
    )
    monkeypatch.setattr(
        "decnet.web.router.swarm_updates.api_push_update_self.detect_git_sha",
        lambda root: "deadbeef",
    )

    return {"client": FakeUpdaterClient, "Response": FakeResponse}


@pytest.fixture
def connection_drop_exc():
    """A realistic 'updater re-exec mid-response' exception."""
    return httpx.RemoteProtocolError("server disconnected")
