# SPDX-License-Identifier: AGPL-3.0-or-later
"""Authorization for the swarm control plane.

Two layers, both fail-closed:
  1. ``_guard_bind`` refuses a routable bind without --tls (CLI startup).
  2. ``require_operator_cert`` gates every controller endpoint (HTTP layer).

No live TLS: the off-box case is simulated by giving the TestClient a
non-loopback client address with no peer cert in scope.
"""
from __future__ import annotations

import pathlib
from typing import Any

import contextlib

import pytest
import typer
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from decnet.cli.swarmctl import _guard_bind
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


@pytest.fixture
def repo(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    r = get_repository(db_path=str(tmp_path / "authz.db"))
    import decnet.web.dependencies as deps
    import decnet.web.swarm_api as swarm_api_mod

    monkeypatch.setattr(deps, "repo", r)
    monkeypatch.setattr(swarm_api_mod, "repo", r)
    return r


@contextlib.contextmanager
def _client(repo, client_addr: tuple[str, int]):
    # The `with TestClient(...)` form runs the controller lifespan, which
    # creates the swarm schema against the test repo.
    from decnet.web.swarm_api import app

    async def _override() -> Any:
        return repo

    app.dependency_overrides[get_repo] = _override
    try:
        with TestClient(app, client=client_addr) as c:
            yield c
    finally:
        app.dependency_overrides.clear()


def test_offbox_certless_caller_is_refused_on_every_operator_route(
    repo, ca_dir: pathlib.Path
) -> None:
    # No TLS peer cert + non-loopback client = an off-box attacker. Every
    # operator route must 403 (the bind guard makes this combination
    # unreachable in production, but the HTTP layer fails closed regardless).
    with _client(repo, ("10.0.0.99", 40000)) as c:
        assert c.post(
            "/swarm/enroll",
            json={"name": "evil", "address": "10.0.0.99", "agent_port": 8765},
        ).status_code == 403
        assert c.get("/swarm/hosts").status_code == 403
        assert c.post("/swarm/check").status_code == 403
        assert c.get("/swarm/deckies").status_code == 403
        assert c.post("/swarm/teardown", json={}).status_code == 403


def test_loopback_operator_is_allowed(repo, ca_dir: pathlib.Path) -> None:
    # The shipping single-host default: local operator over plaintext loopback.
    with _client(repo, ("127.0.0.1", 40000)) as c:
        enrolled = c.post(
            "/swarm/enroll",
            json={"name": "worker-ok", "address": "10.0.0.5", "agent_port": 8765},
        )
        assert enrolled.status_code == 201, enrolled.text
        listed = c.get("/swarm/hosts")
        assert listed.status_code == 200
        assert any(h["name"] == "worker-ok" for h in listed.json())
