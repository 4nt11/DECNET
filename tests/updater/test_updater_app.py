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
def client(tmp_path: pathlib.Path):
    app_mod.configure(
        install_dir=tmp_path / "install",
        updater_install_dir=tmp_path / "install" / "updater",
        agent_dir=tmp_path / "agent",
    )
    (tmp_path / "install" / "releases").mkdir(parents=True)
    # Bypass the master-cert gate for wire-format tests (no live TLS peer).
    app_mod.app.dependency_overrides[app_mod.require_master_cert] = lambda: None
    with TestClient(app_mod.app) as c:
        yield c
    app_mod.app.dependency_overrides.clear()


def test_health_returns_role_and_releases(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ex, "list_releases", lambda d: [])
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["role"] == "updater"
    assert body["releases"] == []


def test_update_happy_path(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def _run_update(data, sha, expected_sha256, install_dir, agent_dir):
        seen["expected_sha256"] = expected_sha256
        return {"status": "updated", "release": {"slot": "active", "sha": sha}, "probe": "ok"}

    monkeypatch.setattr(ex, "run_update", _run_update)
    r = client.post(
        "/update",
        files={"tarball": ("tree.tgz", _tarball(), "application/gzip")},
        data={"sha": "ABC123", "sha256": "0" * 64},
    )
    assert r.status_code == 200, r.text
    assert r.json()["release"]["sha"] == "ABC123"
    # Route forwards the digest verbatim — executor verifies it before extract.
    assert seen["expected_sha256"] == "0" * 64


def test_update_rollback_returns_409(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a, **kw):
        raise ex.UpdateError("probe failed; rolled back", stderr="connection refused", rolled_back=True)
    monkeypatch.setattr(ex, "run_update", _boom)

    r = client.post(
        "/update",
        files={"tarball": ("t.tgz", _tarball(), "application/gzip")},
        data={"sha": "", "sha256": "0" * 64},
    )
    assert r.status_code == 409, r.text
    detail = r.json()["detail"]
    assert detail["rolled_back"] is True
    assert "connection refused" in detail["stderr"]


def test_update_hard_failure_returns_500(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*a, **kw):
        raise ex.UpdateError("pip install failed", stderr="resolver error")
    monkeypatch.setattr(ex, "run_update", _boom)

    r = client.post(
        "/update",
        files={"tarball": ("t.tgz", _tarball(), "application/gzip")},
        data={"sha256": "0" * 64},
    )
    assert r.status_code == 500
    assert r.json()["detail"]["rolled_back"] is False


def test_update_self_requires_confirm(client: TestClient) -> None:
    r = client.post("/update-self", files={"tarball": ("t.tgz", _tarball(), "application/gzip")})
    assert r.status_code == 400
    assert "confirm_self" in r.json()["detail"]


def test_update_self_happy_path(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def _run_update_self(data, sha, updater_install_dir, expected_sha256):
        seen["expected_sha256"] = expected_sha256
        return {"status": "self_update_queued", "argv": ["python", "-m", "decnet", "updater"]}

    monkeypatch.setattr(ex, "run_update_self", _run_update_self)
    r = client.post(
        "/update-self",
        files={"tarball": ("t.tgz", _tarball(), "application/gzip")},
        data={"sha": "S", "sha256": "0" * 64, "confirm_self": "true"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "self_update_queued"
    assert seen["expected_sha256"] == "0" * 64


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


def test_update_without_sha256_is_rejected(client: TestClient) -> None:
    # Mandatory integrity: no checksum → 400, before any extract/install.
    r = client.post(
        "/update",
        files={"tarball": ("t.tgz", _tarball(), "application/gzip")},
        data={"sha": "ABC"},
    )
    assert r.status_code == 400
    assert "sha256" in r.json()["detail"]


def test_update_with_empty_sha256_is_rejected(client: TestClient) -> None:
    # An explicit empty form value is treated the same as absent → 400.
    r = client.post(
        "/update",
        files={"tarball": ("t.tgz", _tarball(), "application/gzip")},
        data={"sha": "ABC", "sha256": ""},
    )
    assert r.status_code == 400
    assert "sha256" in r.json()["detail"]


def test_update_self_without_sha256_is_rejected(client: TestClient) -> None:
    r = client.post(
        "/update-self",
        files={"tarball": ("t.tgz", _tarball(), "application/gzip")},
        data={"confirm_self": "true"},
    )
    assert r.status_code == 400
    assert "sha256" in r.json()["detail"]


def test_update_mismatched_sha256_is_rejected_before_apply(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end through the REAL executor verify: a non-matching digest is a
    500 UpdateError and no extraction/pip happens (extract/_run_pip would be
    reached only AFTER the digest check, so we assert they are never called)."""
    called: list[str] = []
    monkeypatch.setattr(ex, "extract_tarball", lambda *a, **k: called.append("extract"))
    monkeypatch.setattr(ex, "_run_pip", lambda *a, **k: called.append("pip"))

    r = client.post(
        "/update",
        files={"tarball": ("t.tgz", _tarball(), "application/gzip")},
        data={"sha": "ABC", "sha256": "0" * 64},  # wrong digest for this tarball
    )
    assert r.status_code == 500, r.text
    assert "mismatch" in r.json()["detail"]["error"]
    assert called == []  # rejected before any extract/install


# ------------------------- master-cert gate ---------------------------------


@pytest.fixture
def raw_client(tmp_path: pathlib.Path):
    """Client with the real require_master_cert gate active (no override)."""
    app_mod.configure(
        install_dir=tmp_path / "install",
        updater_install_dir=tmp_path / "install" / "updater",
        agent_dir=tmp_path / "agent",
    )
    (tmp_path / "install" / "releases").mkdir(parents=True)
    with TestClient(app_mod.app) as c:
        yield c


@pytest.mark.parametrize("path", ["/update", "/update-self", "/rollback", "/releases"])
def test_endpoints_reject_callers_without_master_cert(raw_client: TestClient, path: str) -> None:
    # No TLS peer cert in a TestClient scope → require_master_cert fails closed.
    if path == "/rollback":
        r = raw_client.post(path)
    elif path == "/releases":
        r = raw_client.get(path)
    else:
        r = raw_client.post(
            path,
            files={"tarball": ("t.tgz", _tarball(), "application/gzip")},
            data={"sha256": "0" * 64, "confirm_self": "true"},
        )
    assert r.status_code == 403
    assert "master certificate" in r.json()["detail"]


def test_require_master_cert_accepts_decnet_master(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from unittest.mock import MagicMock

    from decnet.swarm import pki
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    monkeypatch.setattr(pki, "DEFAULT_CA_DIR", tmp_path / "ca")
    ca = pki.ensure_ca()

    def _der(cn: str) -> bytes:
        issued = pki.issue_worker_cert(ca, cn, [])
        cert = x509.load_pem_x509_certificate(issued.cert_pem)
        return cert.public_bytes(serialization.Encoding.DER)

    def _req(cn: str) -> MagicMock:
        req = MagicMock()
        req.scope = {"extensions": {"tls": {"client_cert_chain": [_der(cn)]}}}
        return req

    # master cert → allowed (returns None)
    assert app_mod.require_master_cert(_req("decnet-master")) is None
    # a worker/agent cert is CA-signed but must be rejected
    with pytest.raises(app_mod.HTTPException) as ei:
        app_mod.require_master_cert(_req("worker-7"))
    assert ei.value.status_code == 403
