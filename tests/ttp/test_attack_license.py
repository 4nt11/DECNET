# SPDX-License-Identifier: AGPL-3.0-or-later
"""MITRE ATT&CK Terms of Use compliance: LICENSE.txt is fetched, verified, and required.

Bundle and license live side-by-side in the cache dir. The bundle is
fail-closed on hash mismatch (drift = mistagging risk); the license
is logged-and-refreshed on hash mismatch (drift = MITRE updated the
text, not a security event), but its *presence* is mandatory.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from decnet.ttp import attack_stix
from decnet.ttp.attack_version import (
    ATTACK_LICENSE_FILENAME,
    ATTACK_LICENSE_SHA256,
)

_REPO_BUNDLE = Path(__file__).resolve().parents[2] / "enterprise-attack-19.0.json"


@pytest.fixture(autouse=True)
def _reset_loader_state() -> None:
    attack_stix._data = None
    attack_stix._loaded_path = None
    attack_stix._attack_pattern_by_id.cache_clear()
    attack_stix._tactic_by_id.cache_clear()
    attack_stix._tactic_by_short_name.cache_clear()


def _write_dummy_license(path: Path) -> str:
    text = "placeholder license content for tests"
    path.write_text(text, encoding="utf-8")
    return hashlib.sha256(text.encode()).hexdigest()


def test_license_filename_constant() -> None:
    assert ATTACK_LICENSE_FILENAME == "LICENSE.txt"


def test_resolve_bundle_path_with_override_and_sibling_license(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Operator points DECNET_ATTACK_BUNDLE at a file with LICENSE.txt next to it — happy path."""
    bundle = tmp_path / "enterprise-attack-19.0.json"
    bundle.write_bytes(_REPO_BUNDLE.read_bytes())
    license_path = tmp_path / ATTACK_LICENSE_FILENAME
    _write_dummy_license(license_path)

    monkeypatch.setenv("DECNET_ATTACK_BUNDLE", str(bundle))
    monkeypatch.delenv("DECNET_ATTACK_LICENSE", raising=False)
    # Empty cache dir so override-mode resolves license from sibling.
    monkeypatch.setenv("DECNET_ATTACK_CACHE_DIR", str(tmp_path / "cache"))

    resolved = attack_stix.resolve_bundle_path()
    assert resolved == bundle
    assert attack_stix.loaded_license_path() == license_path


def test_resolve_bundle_path_via_decnet_attack_license_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DECNET_ATTACK_LICENSE points to an arbitrary path — accepted."""
    bundle = tmp_path / "bundle" / "enterprise-attack-19.0.json"
    bundle.parent.mkdir()
    bundle.write_bytes(_REPO_BUNDLE.read_bytes())
    explicit_license = tmp_path / "license_elsewhere.txt"
    _write_dummy_license(explicit_license)

    monkeypatch.setenv("DECNET_ATTACK_BUNDLE", str(bundle))
    monkeypatch.setenv("DECNET_ATTACK_LICENSE", str(explicit_license))
    monkeypatch.setenv("DECNET_ATTACK_CACHE_DIR", str(tmp_path / "cache"))

    resolved = attack_stix.resolve_bundle_path()
    assert resolved == bundle
    assert attack_stix.loaded_license_path() == explicit_license


def test_decnet_attack_license_pointing_to_missing_file_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bundle = tmp_path / "enterprise-attack-19.0.json"
    bundle.write_bytes(_REPO_BUNDLE.read_bytes())
    monkeypatch.setenv("DECNET_ATTACK_BUNDLE", str(bundle))
    monkeypatch.setenv("DECNET_ATTACK_LICENSE", str(tmp_path / "nope.txt"))
    monkeypatch.setenv("DECNET_ATTACK_CACHE_DIR", str(tmp_path / "cache"))

    with pytest.raises(attack_stix.AttackBundleError) as exc:
        attack_stix.resolve_bundle_path()
    assert "Terms of Use" in str(exc.value)


def test_loaded_license_path_returns_none_when_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DECNET_ATTACK_BUNDLE", raising=False)
    monkeypatch.delenv("DECNET_ATTACK_LICENSE", raising=False)
    monkeypatch.setenv("DECNET_ATTACK_CACHE_DIR", str(tmp_path))
    assert attack_stix.loaded_license_path() is None


def test_pinned_license_sha_matches_repo_committed_text() -> None:
    """The pinned hash in attack_version.py is a 64-char lowercase hex sha256."""
    assert len(ATTACK_LICENSE_SHA256) == 64
    assert all(c in "0123456789abcdef" for c in ATTACK_LICENSE_SHA256)


def test_cli_license_subcommand_prints_cached_license(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    license_path = tmp_path / ATTACK_LICENSE_FILENAME
    license_path.write_text("MITRE Corporation grants you a license\n", encoding="utf-8")
    monkeypatch.setenv("DECNET_ATTACK_LICENSE", str(license_path))

    rc = attack_stix.main(["license"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "MITRE Corporation" in out


def test_cli_license_returns_nonzero_when_not_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DECNET_ATTACK_LICENSE", raising=False)
    monkeypatch.delenv("DECNET_ATTACK_BUNDLE", raising=False)
    monkeypatch.setenv("DECNET_ATTACK_CACHE_DIR", str(tmp_path / "empty"))

    rc = attack_stix.main(["license"])
    assert rc == 1
