# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authorization for the swarm control plane.

Three fail-closed layers:
  1. ``_guard_bind`` refuses a routable bind without --tls (CLI startup).
  2. ``require_admin`` (centralized RBAC) gates every operator endpoint with an
     admin-role JWT (HTTP layer, primary application-layer gate).
  3. ``require_operator_cert`` is the transport gate (mTLS operator CN, or a
     loopback request) — defense-in-depth, no longer the only gate.

No live TLS: the off-box case is simulated by giving the TestClient a
non-loopback client address with no peer cert in scope. The JWT layer is
exercised with real HS256 tokens minted against the test repo.
"""
from __future__ import annotations

import pathlib
import uuid as _uuid
from typing import Any

import contextlib

import pytest
import typer
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from decnet.cli.swarmctl import _guard_bind
from decnet.web.auth import create_access_token, get_password_hash
from decnet.web.db.factory import get_repository
from decnet.web.dependencies import get_repo


# ------------------------- layer 1: bind guard ------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_guard_bind_allows_loopback_plaintext(host: str) -> None:
    _guard_bind(host, tls=False)  # must not raise


@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.5", "192.168.1.10"])
def test_guard_bind_allows_routable_with_tls(host: str) -> None:
    _guard_bind(host, tls=True)  # mTLS makes a routable bind legitimate


@pytest.mark.parametrize("host", ["0.0.0.0", "10.0.0.5"])
def test_guard_bind_refuses_routable_plaintext(host: str) -> None:
    with pytest.raises(typer.Exit) as ei:
        _guard_bind(host, tls=False)
    assert ei.value.exit_code == 2


def test_swarmctl_cli_refuses_routable_plaintext(monkeypatch: pytest.MonkeyPatch) -> None:
    # Wiring check: the guard fires before any subprocess is spawned.
    import subprocess

    from decnet.cli import app

    called = {"popen": False}

    def _no_popen(*a: Any, **k: Any):  # pragma: no cover - must not run
        called["popen"] = True
        raise AssertionError("subprocess.Popen must not be reached")

    monkeypatch.setattr(subprocess, "Popen", _no_popen)
    result = CliRunner().invoke(app, ["swarmctl", "--host", "0.0.0.0", "--no-listener"])
    assert result.exit_code == 2
    assert called["popen"] is False


# ------------------------- layer 2: endpoint operator gate ------------------


@pytest.fixture
def ca_dir(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    ca = tmp_path / "ca"
    from decnet.swarm import pki
    from decnet.web.router.swarm import api_enroll_host as enroll_mod

    monkeypatch.setattr(pki, "DEFAULT_CA_DIR", ca)
    monkeypatch.setattr(enroll_mod, "pki", pki)
    return ca


ADMIN_UUID = "admin-uuid-authz"
VIEWER_UUID = "viewer-uuid-authz"


@pytest.fixture
def repo(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    r = get_repository(db_path=str(tmp_path / "authz.db"))
    import decnet.web.dependencies as deps
    import decnet.web.swarm_api as swarm_api_mod

    monkeypatch.setattr(deps, "repo", r)
    monkeypatch.setattr(swarm_api_mod, "repo", r)
    # require_admin caches user lookups for 10s; clear so a freshly-seeded
    # user is visible and doesn't leak across tests.
    deps._reset_user_cache()
    return r


async def _seed_users(repo) -> None:
    """Seed one admin and one viewer so require_admin has real rows to resolve."""
    await repo.create_user({
        "uuid": ADMIN_UUID,
        "username": "authz-admin",
        "password_hash": get_password_hash("x"),
        "role": "admin",
        "must_change_password": False,
    })
    await repo.create_user({
        "uuid": VIEWER_UUID,
        "username": "authz-viewer",
        "password_hash": get_password_hash("x"),
        "role": "viewer",
        "must_change_password": False,
    })


def _token(user_uuid: str) -> str:
    # Mirrors api_login: uuid + per-token jti (the denylist key). create_access_token
    # stamps exp + iat. Role is resolved from the DB row by require_admin, not the token.
    return create_access_token(data={"uuid": user_uuid, "jti": _uuid.uuid4().hex})


def _admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(ADMIN_UUID)}"}


def _viewer_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(VIEWER_UUID)}"}


@contextlib.contextmanager
def _client(repo, client_addr: tuple[str, int]):
    # The `with TestClient(...)` form runs the controller lifespan, which
    # creates the swarm schema against the test repo.
    import decnet.web.dependencies as deps
    from decnet.web.dependencies import require_admin
    from decnet.web.swarm_api import app

    async def _override() -> Any:
        return repo

    app.dependency_overrides[get_repo] = _override
    # This file is the source of truth for the JWT gate — drop the autouse
    # bypass installed by conftest so the REAL require_admin runs here.
    app.dependency_overrides.pop(require_admin, None)
    # The auth caches are module-global; a prior test may have cached a MISS
    # for our seeded uuids. Clear so require_admin resolves the fresh rows.
    deps._reset_user_cache()
    try:
        with TestClient(app, client=client_addr) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


# Every operator route, with a body that gets past validation so the only
# thing that can reject the request is the auth layer.
# For {uuid} routes a syntactically-valid UUID is used: the auth gate fires
# before the repo lookup, so 401/403 is the only possible outcome without a
# valid token. In the admin happy-path tests a real host is seeded so that
# 200/204 confirms end-to-end gate passage.
_OPERATOR_ROUTES: list[tuple[str, str, dict | None]] = [
    ("POST", "/swarm/enroll", {"name": "x", "address": "10.0.0.1", "agent_port": 8765}),
    ("GET", "/swarm/hosts", None),
    ("POST", "/swarm/check", None),
    ("GET", "/swarm/deckies", None),
    ("POST", "/swarm/teardown", {}),
    (
        "POST",
        "/swarm/deploy",
        {
            "config": {
                "mode": "swarm",
                "interface": "eth0",
                "subnet": "10.99.0.0/24",
                "gateway": "10.99.0.1",
                "deckies": [
                    {
                        "name": "authz-probe",
                        "ip": "10.99.0.2",
                        "services": ["ssh"],
                        "distro": "debian",
                        "base_image": "debian:bookworm-slim",
                        "hostname": "probe01",
                        "host_uuid": "00000000-0000-0000-0000-000000000001",
                    }
                ],
            }
        },
    ),
    ("GET", "/swarm/hosts/00000000-0000-0000-0000-000000000099", None),
    ("DELETE", "/swarm/hosts/00000000-0000-0000-0000-000000000099", None),
]


def test_offbox_certless_caller_is_refused_on_every_operator_route(
    repo, ca_dir: pathlib.Path
) -> None:
    # No JWT + no TLS peer cert + non-loopback client = an off-box attacker.
    # The JWT gate runs first, so the refusal is 401 (and the cert gate would
    # 403 it regardless). Either way: fail closed on every operator route.
    with _client(repo, ("10.0.0.99", 40000)) as c:
        for method, path, body in _OPERATOR_ROUTES:
            resp = c.request(method, path, json=body)
            assert resp.status_code in (401, 403), f"{method} {path} -> {resp.status_code}"


def test_loopback_without_jwt_is_now_rejected(repo, ca_dir: pathlib.Path) -> None:
    # REGRESSION GUARD (V4.1.1a): loopback transport alone is no longer enough.
    # A local caller with no admin JWT must be refused — this is the whole point
    # of layering require_admin on top of the loopback trust boundary.
    import anyio
    with _client(repo, ("127.0.0.1", 40000)) as c:
        anyio.run(lambda: _seed_users(repo))  # schema is live once lifespan ran
        for method, path, body in _OPERATOR_ROUTES:
            resp = c.request(method, path, json=body)
            assert resp.status_code == 401, f"{method} {path} -> {resp.status_code}"


def test_loopback_viewer_jwt_is_forbidden(repo, ca_dir: pathlib.Path) -> None:
    # A valid but non-admin JWT must be rejected by the role gate (403) on
    # every operator route, not just GET /swarm/hosts.
    import anyio
    with _client(repo, ("127.0.0.1", 40000)) as c:
        anyio.run(lambda: _seed_users(repo))
        for method, path, body in _OPERATOR_ROUTES:
            resp = c.request(method, path, json=body, headers=_viewer_headers())
            assert resp.status_code == 403, f"{method} {path} -> {resp.status_code}"


def test_loopback_admin_jwt_is_allowed(repo, ca_dir: pathlib.Path) -> None:
    # The shipping single-host default: local operator over plaintext loopback,
    # now carrying an admin JWT. Both gates pass -> the request succeeds or
    # produces a domain error (never 401/403).
    import anyio
    import decnet.web.router.swarm.api_deploy_swarm as deploy_mod

    with _client(repo, ("127.0.0.1", 40000)) as c:
        anyio.run(lambda: _seed_users(repo))

        # ---- enroll a host so uuid-based routes have a real target ----
        enrolled = c.post(
            "/swarm/enroll",
            json={"name": "worker-ok", "address": "10.0.0.5", "agent_port": 8765},
            headers=_admin_headers(),
        )
        assert enrolled.status_code == 201, enrolled.text
        host_uuid = enrolled.json()["host_uuid"]

        # GET /swarm/hosts — original assertion preserved
        listed = c.get("/swarm/hosts", headers=_admin_headers())
        assert listed.status_code == 200
        assert any(h["name"] == "worker-ok" for h in listed.json())

        # GET /swarm/hosts/{uuid} — auth gate passes; real host found -> 200
        got = c.get(f"/swarm/hosts/{host_uuid}", headers=_admin_headers())
        assert got.status_code == 200, got.text
        assert got.json()["uuid"] == host_uuid

        # POST /swarm/deploy — mock dispatch to avoid live AgentClient calls;
        # assert auth passes (would be 401/403 if the gate rejected).
        from decnet.web.db.models import SwarmDeployResponse
        async def _fake_dispatch(config, repo, dry_run=False, no_cache=False):
            return SwarmDeployResponse(results=[])
        deploy_mod.dispatch_decnet_config = _fake_dispatch
        try:
            deploy_resp = c.post(
                "/swarm/deploy",
                json={
                    "config": {
                        "mode": "swarm",
                        "interface": "eth0",
                        "subnet": "10.99.0.0/24",
                        "gateway": "10.99.0.1",
                        "deckies": [
                            {
                                "name": "authz-probe",
                                "ip": "10.99.0.2",
                                "services": ["ssh"],
                                "distro": "debian",
                                "base_image": "debian:bookworm-slim",
                                "hostname": "probe01",
                                "host_uuid": host_uuid,
                            }
                        ],
                    }
                },
                headers=_admin_headers(),
            )
            assert deploy_resp.status_code not in (401, 403), (
                f"POST /swarm/deploy auth gate rejected: {deploy_resp.status_code}"
            )
        finally:
            # Restore the real dispatch so other tests aren't affected
            import importlib
            importlib.reload(deploy_mod)

        # DELETE /swarm/hosts/{uuid} — auth gate passes; host deleted -> 204
        # Enroll a second host specifically to delete so worker-ok stays available
        enrolled2 = c.post(
            "/swarm/enroll",
            json={"name": "worker-del", "address": "10.0.0.6", "agent_port": 8765},
            headers=_admin_headers(),
        )
        assert enrolled2.status_code == 201, enrolled2.text
        del_uuid = enrolled2.json()["host_uuid"]

        # Mock AgentClient.self_destruct so DELETE doesn't attempt a real network call
        from unittest.mock import AsyncMock, patch
        with patch(
            "decnet.web.router.swarm.api_decommission_host.AgentClient"
        ) as mock_agent_cls:
            mock_ctx = AsyncMock()
            mock_ctx.self_destruct = AsyncMock(return_value=None)
            mock_agent_cls.return_value.__aenter__ = AsyncMock(return_value=mock_ctx)
            mock_agent_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            deleted = c.delete(f"/swarm/hosts/{del_uuid}", headers=_admin_headers())
        assert deleted.status_code == 204, deleted.text
