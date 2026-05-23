# SPDX-License-Identifier: AGPL-3.0-or-later
"""HTTP contract for the updater app.

Executor functions are monkeypatched — we're testing wire format, not
the rotation logic (that has test_updater_executor.py).
"""
from __future__ import annotations

import io
import pathlib
import tarfile

import pytest
from fastapi.testclient import TestClient

from decnet.updater import app as app_mod
from decnet.updater import executor as ex


def _tarball(files: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in (files or {"a": "b"}).items():
            data = content.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def client(tmp_path: pathlib.Path) -> TestClient:
    app_mod.configure(
        install_dir=tmp_path / "install",
        updater_install_dir=tmp_path / "install" / "updater",
        agent_dir=tmp_path / "agent",
    )
    (tmp_path / "install" / "releases").mkdir(parents=True)
    return TestClient(app_mod.app)


def test_health_returns_role_and_releases(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ex, "list_releases", lambda d: [])
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["role"] == "updater"
    assert body["releases"] == []


def test_update_happy_path(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ex, "run_update",
        lambda data, sha, install_dir, agent_dir, expected_sha256=None: {"status": "updated", "release": {"slot": "active", "sha": sha}, "probe": "ok"},
    )
    r = client.post(
        "/update",
        files={"tarball": ("tree.tgz", _tarball(), "application/gzip")},
        data={"sha": "ABC123"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["release"]["sha"] == "ABC123"


def test_update_rollback_returns_409(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a, **kw):
        raise ex.UpdateError("probe failed; rolled back", stderr="connection refused", rolled_back=True)
    monkeypatch.setattr(ex, "run_update", _boom)

    r = client.post(
        "/update",
        files={"tarball": ("t.tgz", _tarball(), "application/gzip")},
        data={"sha": ""},
    )
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert detail["rolled_back"] is True
    assert "connection refused" in detail["stderr"]


def test_update_hard_failure_returns_500(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a, **kw):
        raise ex.UpdateError("pip install failed", stderr="resolver error")
    monkeypatch.setattr(ex, "run_update", _boom)

    r = client.post("/update", files={"tarball": ("t.tgz", _tarball(), "application/gzip")})
    assert r.status_code == 500
    assert r.json()["detail"]["rolled_back"] is False


def test_update_self_requires_confirm(client: TestClient) -> None:
    r = client.post("/update-self", files={"tarball": ("t.tgz", _tarball(), "application/gzip")})
    assert r.status_code == 400
    assert "confirm_self" in r.json()["detail"]


def test_update_self_happy_path(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ex, "run_update_self",
        lambda data, sha, updater_install_dir, expected_sha256=None: {"status": "self_update_queued", "argv": ["python", "-m", "decnet", "updater"]},
    )
    r = client.post(
        "/update-self",
        files={"tarball": ("t.tgz", _tarball(), "application/gzip")},
        data={"sha": "S", "confirm_self": "true"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "self_update_queued"


def test_rollback_happy(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ex, "run_rollback",
        lambda install_dir, agent_dir: {"status": "rolled_back", "release": {"slot": "active", "sha": "O"}, "probe": "ok"},
    )
    r = client.post("/rollback")
    assert r.status_code == 200
    assert r.json()["status"] == "rolled_back"


def test_rollback_missing_prev_returns_404(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(**_):
        raise ex.UpdateError("no previous release to roll back to")
    monkeypatch.setattr(ex, "run_rollback", _boom)
    r = client.post("/rollback")
    assert r.status_code == 404


def test_releases_lists_slots(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ex, "list_releases",
        lambda d: [ex.Release(slot="active", sha="A", installed_at=None),
                   ex.Release(slot="prev", sha="B", installed_at=None)],
    )
    r = client.get("/releases")
    assert r.status_code == 200
    slots = [rel["slot"] for rel in r.json()["releases"]]
    assert slots == ["active", "prev"]
