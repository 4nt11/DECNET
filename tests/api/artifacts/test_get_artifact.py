"""
Tests for GET /api/v1/artifacts/{decky}/{stored_as}.

Verifies admin-gating, 404 on missing files, 400 on malformed inputs, and
that path traversal attempts cannot escape DECNET_ARTIFACTS_ROOT.
"""

from __future__ import annotations

import httpx
import pytest


_DECKY = "test-decky-01"
_VALID_STORED_AS = "2026-04-18T02:22:56Z_abc123def456_payload.bin"
_PAYLOAD = b"attacker-drop-bytes\x00\x01\x02\xff"


@pytest.fixture
def artifacts_root(tmp_path, monkeypatch):
    """Point the artifact endpoint at a tmp dir and seed one valid file."""
    root = tmp_path / "artifacts"
    (root / _DECKY / "ssh").mkdir(parents=True)
    (root / _DECKY / "ssh" / _VALID_STORED_AS).write_bytes(_PAYLOAD)

    # Patch the module-level constant (captured at import time).
    from decnet.web.router.artifacts import api_get_artifact
    monkeypatch.setattr(api_get_artifact, "ARTIFACTS_ROOT", root)
    return root


async def test_admin_downloads_artifact(client: httpx.AsyncClient, auth_token: str, artifacts_root):
    res = await client.get(
        f"/api/v1/artifacts/{_DECKY}/{_VALID_STORED_AS}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 200, res.text
    assert res.content == _PAYLOAD
    assert res.headers["content-type"] == "application/octet-stream"


async def test_viewer_forbidden(client: httpx.AsyncClient, viewer_token: str, artifacts_root):
    res = await client.get(
        f"/api/v1/artifacts/{_DECKY}/{_VALID_STORED_AS}",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert res.status_code == 403


async def test_unauthenticated_rejected(client: httpx.AsyncClient, artifacts_root):
    res = await client.get(f"/api/v1/artifacts/{_DECKY}/{_VALID_STORED_AS}")
    assert res.status_code == 401


async def test_missing_file_returns_404(client: httpx.AsyncClient, auth_token: str, artifacts_root):
    missing = "2026-04-18T02:22:56Z_000000000000_nope.bin"
    res = await client.get(
        f"/api/v1/artifacts/{_DECKY}/{missing}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 404


@pytest.mark.parametrize("bad_decky", [
    "UPPERCASE",
    "has_underscore",
    "has.dot",
    "-leading-hyphen",
    "",
    "a/b",
])
async def test_bad_decky_rejected(client: httpx.AsyncClient, auth_token: str, artifacts_root, bad_decky):
    res = await client.get(
        f"/api/v1/artifacts/{bad_decky}/{_VALID_STORED_AS}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # FastAPI returns 404 for routes that fail to match (e.g. `a/b` splits the
    # path param); malformed-but-matching cases yield our 400.
    assert res.status_code in (400, 404)


@pytest.mark.parametrize("bad_stored_as", [
    "not-a-timestamp_abc123def456_payload.bin",
    "2026-04-18T02:22:56Z_SHORT_payload.bin",
    "2026-04-18T02:22:56Z_abc123def456_",
    "random-string",
    "",
])
async def test_bad_stored_as_rejected(client: httpx.AsyncClient, auth_token: str, artifacts_root, bad_stored_as):
    res = await client.get(
        f"/api/v1/artifacts/{_DECKY}/{bad_stored_as}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code in (400, 404)


async def test_path_traversal_blocked(client: httpx.AsyncClient, auth_token: str, artifacts_root, tmp_path):
    """A file placed outside the artifacts root must be unreachable even if a
    caller crafts a URL-encoded `..` in the stored_as segment."""
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"top-secret")
    # The regex for stored_as forbids slashes, `..`, etc. Any encoding trick
    # that reaches the handler must still fail the regex → 400.
    for payload in (
        "..%2Fsecret.txt",
        "..",
        "../../etc/passwd",
        "%2e%2e/%2e%2e/etc/passwd",
    ):
        res = await client.get(
            f"/api/v1/artifacts/{_DECKY}/{payload}",
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        # Either 400 (our validator) or 404 (FastAPI didn't match the route) is fine;
        # what's NOT fine is 200 with secret bytes.
        assert res.status_code != 200
        assert b"top-secret" not in res.content


async def test_content_disposition_is_attachment(client: httpx.AsyncClient, auth_token: str, artifacts_root):
    res = await client.get(
        f"/api/v1/artifacts/{_DECKY}/{_VALID_STORED_AS}",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 200
    cd = res.headers.get("content-disposition", "")
    assert "attachment" in cd.lower()


async def test_smtp_service_serves_from_smtp_subdir(
    client: httpx.AsyncClient, auth_token: str, tmp_path, monkeypatch,
):
    """?service=smtp routes to {root}/{decky}/smtp/ instead of .../ssh/."""
    root = tmp_path / "artifacts-smtp"
    (root / _DECKY / "smtp").mkdir(parents=True)
    eml = "2026-04-18T02:22:56Z_abc123def456_msg.eml"
    (root / _DECKY / "smtp" / eml).write_bytes(b"From: a\r\n\r\nhi")
    from decnet.web.router.artifacts import api_get_artifact
    monkeypatch.setattr(api_get_artifact, "ARTIFACTS_ROOT", root)
    res = await client.get(
        f"/api/v1/artifacts/{_DECKY}/{eml}?service=smtp",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    assert res.status_code == 200
    assert res.content == b"From: a\r\n\r\nhi"


async def test_unknown_service_rejected(
    client: httpx.AsyncClient, auth_token: str, artifacts_root,
):
    res = await client.get(
        f"/api/v1/artifacts/{_DECKY}/{_VALID_STORED_AS}?service=rdp",
        headers={"Authorization": f"Bearer {auth_token}"},
    )
    # Regex matches (lowercase alpha) but _ALLOWED_SERVICES rejects → 400.
    assert res.status_code == 400
