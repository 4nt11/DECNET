"""Tests for ``POST /api/v1/workers/{name}/start`` + ``start-all``.

Uses the shared ``client`` / ``auth_token`` / ``viewer_token`` fixtures
from ``tests/api/conftest.py``.  Stubs out ``systemd_control`` so tests
never touch real systemctl.
"""
from __future__ import annotations

from typing import Any, Set

import httpx
import pytest

from decnet.web.router.workers import api_list_workers as _list
from decnet.web.router.workers import api_start_all_workers as _start_all
from decnet.web.router.workers import api_start_worker as _start
from decnet.web.services import systemd_control as _sc


def _patch_installed(monkeypatch: Any, names: Set[str]) -> None:
    async def _stub() -> Set[str]:
        return set(names)

    # Each module imported `systemd_control` directly; patch on the
    # module-level attribute so all three endpoints see the stub.
    for mod in (_start, _start_all, _list):
        monkeypatch.setattr(mod.systemd_control, "list_installed", _stub)


def _patch_start(monkeypatch: Any, *, raises: _sc.SystemctlError | None = None) -> list[str]:
    calls: list[str] = []

    async def _stub(name: str) -> None:
        calls.append(name)
        if raises is not None:
            raise raises

    monkeypatch.setattr(_sc, "start", _stub)
    return calls


def _patch_is_active(monkeypatch: Any, active: Set[str]) -> None:
    async def _stub(name: str) -> bool:
        return name in active

    monkeypatch.setattr(_sc, "is_active", _stub)


@pytest.mark.asyncio
async def test_start_worker_admin_happy_path(
    client: httpx.AsyncClient, auth_token: str, monkeypatch,
) -> None:
    _patch_installed(monkeypatch, {"mutator", "bus"})
    calls = _patch_start(monkeypatch)
    resp = await client.post(
        "/api/v1/workers/mutator/start",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body == {"accepted": True, "worker": "mutator", "action": "start"}
    assert calls == ["mutator"]


@pytest.mark.asyncio
async def test_start_worker_viewer_forbidden(
    client: httpx.AsyncClient, viewer_token: str, monkeypatch,
) -> None:
    _patch_installed(monkeypatch, {"mutator"})
    _patch_start(monkeypatch)
    resp = await client.post(
        "/api/v1/workers/mutator/start",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_start_worker_unknown_name_404(
    client: httpx.AsyncClient, auth_token: str, monkeypatch,
) -> None:
    _patch_installed(monkeypatch, {"mutator"})
    _patch_start(monkeypatch)
    resp = await client.post(
        "/api/v1/workers/nosuch/start",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_start_worker_not_installed_503(
    client: httpx.AsyncClient, auth_token: str, monkeypatch,
) -> None:
    _patch_installed(monkeypatch, set())  # nothing installed
    _patch_start(monkeypatch)
    resp = await client.post(
        "/api/v1/workers/mutator/start",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_start_worker_systemctl_failure_502(
    client: httpx.AsyncClient, auth_token: str, monkeypatch,
) -> None:
    _patch_installed(monkeypatch, {"mutator"})
    err = _sc.SystemctlError(
        unit="decnet-mutator.service",
        returncode=1,
        stderr="Failed to start decnet-mutator.service: unit not found",
    )
    _patch_start(monkeypatch, raises=err)
    resp = await client.post(
        "/api/v1/workers/mutator/start",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 502
    body = resp.json()
    assert "not found" in body["detail"]


@pytest.mark.asyncio
async def test_start_all_aggregates_success_running_and_failure(
    client: httpx.AsyncClient, auth_token: str, monkeypatch,
) -> None:
    _patch_installed(monkeypatch, {"bus", "api", "mutator"})
    _patch_is_active(monkeypatch, {"bus"})  # bus is already running

    async def _stub_start(name: str) -> None:
        if name == "mutator":
            raise _sc.SystemctlError(
                unit="decnet-mutator.service",
                returncode=1,
                stderr="Unit decnet-mutator.service is masked.",
            )
        # api starts cleanly

    monkeypatch.setattr(_sc, "start", _stub_start)

    resp = await client.post(
        "/api/v1/workers/start-all",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["already_running"] == ["bus"]
    assert body["started"] == ["api"]
    assert len(body["failed"]) == 1
    assert body["failed"][0]["name"] == "mutator"
    assert "masked" in body["failed"][0]["reason"]


@pytest.mark.asyncio
async def test_start_all_viewer_forbidden(
    client: httpx.AsyncClient, viewer_token: str, monkeypatch,
) -> None:
    _patch_installed(monkeypatch, {"bus"})
    resp = await client.post(
        "/api/v1/workers/start-all",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_start_all_skips_uninstalled(
    client: httpx.AsyncClient, auth_token: str, monkeypatch,
) -> None:
    _patch_installed(monkeypatch, set())  # no units installed
    _patch_is_active(monkeypatch, set())
    _patch_start(monkeypatch)
    resp = await client.post(
        "/api/v1/workers/start-all",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"started": [], "already_running": [], "failed": []}
