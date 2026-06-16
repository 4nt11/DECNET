"""Unit tests for decnet.artifacts.paths.resolve_artifact_path."""

from __future__ import annotations

import os
import pytest

from decnet.artifacts import paths as artifact_paths
from decnet.artifacts.paths import ArtifactPathError, resolve_artifact_path


_DECKY = "test-decky-01"
_VALID_STORED_AS = "2026-04-18T02:22:56Z_abc123def456_payload.bin"


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(artifact_paths, "ARTIFACTS_ROOT", tmp_path)
    return tmp_path


def test_valid_ssh_path(root):
    p = resolve_artifact_path(_DECKY, _VALID_STORED_AS, "ssh")
    assert p == (root / _DECKY / "ssh" / _VALID_STORED_AS).resolve()


def test_valid_smtp_path(root):
    eml = "2026-04-18T02:22:56Z_abc123def456_msg.eml"
    p = resolve_artifact_path(_DECKY, eml, "smtp")
    assert p == (root / _DECKY / "smtp" / eml).resolve()


@pytest.mark.parametrize("service", ["rdp", "telnet", "", "../etc", "ssh/../smtp"])
def test_invalid_service(root, service):
    with pytest.raises(ArtifactPathError, match="invalid service"):
        resolve_artifact_path(_DECKY, _VALID_STORED_AS, service)


@pytest.mark.parametrize("decky", [
    "UPPERCASE", "has_underscore", "has.dot", "-leading-hyphen",
    "", "a/b", "..",
])
def test_invalid_decky(root, decky):
    with pytest.raises(ArtifactPathError, match="invalid decky name"):
        resolve_artifact_path(decky, _VALID_STORED_AS, "ssh")


@pytest.mark.parametrize("stored_as", [
    "not-a-timestamp_abc123def456_payload.bin",
    "2026-04-18T02:22:56Z_SHORT_payload.bin",
    "2026-04-18T02:22:56Z_abc123def456_",
    "random-string",
    "",
    "../../etc/passwd",
])
def test_invalid_stored_as(root, stored_as):
    with pytest.raises(ArtifactPathError, match="invalid stored_as"):
        resolve_artifact_path(_DECKY, stored_as, "ssh")


def test_symlink_escape_blocked(tmp_path, monkeypatch):
    """A symlink inside the artifacts tree pointing outside must not let
    resolve_artifact_path return a path outside the root."""
    real_root = tmp_path / "real"
    real_root.mkdir()
    secret_dir = tmp_path / "outside"
    secret_dir.mkdir()
    (secret_dir / _VALID_STORED_AS).write_bytes(b"secret")

    decky_dir = real_root / _DECKY
    decky_dir.mkdir()
    # symlink the entire ssh subdir to the outside location
    os.symlink(secret_dir, decky_dir / "ssh")

    monkeypatch.setattr(artifact_paths, "ARTIFACTS_ROOT", real_root)

    with pytest.raises(ArtifactPathError, match="escapes"):
        resolve_artifact_path(_DECKY, _VALID_STORED_AS, "ssh")


def test_does_not_check_existence(root):
    """Helper validates and resolves; existence is the caller's problem."""
    p = resolve_artifact_path(_DECKY, _VALID_STORED_AS, "ssh")
    assert not p.exists()
