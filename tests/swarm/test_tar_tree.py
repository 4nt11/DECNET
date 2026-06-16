# SPDX-License-Identifier: AGPL-3.0-or-later
"""tar_working_tree: include allowlist, secret exclusion, tarball validity, git SHA."""
from __future__ import annotations

import io
import pathlib
import tarfile

from decnet.swarm.tar_tree import detect_git_sha, tar_working_tree


def _tree_names(data: bytes) -> set[str]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        return {m.name for m in tar.getmembers()}


def _seed_tree(root: pathlib.Path) -> None:
    """A realistic master working tree: package + metadata + a pile of junk
    and secrets that must NOT ship."""
    (root / "decnet").mkdir()
    (root / "decnet" / "__init__.py").write_text("")
    (root / "decnet" / "agent.py").write_text("x = 1")
    (root / "decnet" / "templates").mkdir()
    (root / "decnet" / "templates" / "base.j2").write_text("data")
    (root / "decnet" / "__pycache__").mkdir()
    (root / "decnet" / "__pycache__" / "agent.cpython-311.pyc").write_text("bytecode")
    (root / "pyproject.toml").write_text("[project]\nname='decnet'\n")
    (root / "LICENSE").write_text("AGPL")
    (root / "README.md").write_text("# decnet")
    # ---- secrets / junk that the OLD exclude-list would have leaked ----
    (root / ".env.local").write_text("DECNET_JWT_SECRET=topsecret")
    (root / ".env").write_text("X=Y")
    (root / "tls.key").write_text("-----BEGIN PRIVATE KEY-----")
    (root / "ca.pem").write_text("-----BEGIN CERTIFICATE-----")
    (root / "decnet.db").write_text("sqlite")
    (root / "master.log").write_text("log")
    (root / "decnet_web").mkdir()  # dashboard source — not a package
    (root / "decnet_web" / "app.tsx").write_text("ui")
    (root / "tests").mkdir()
    (root / "tests" / "test_x.py").write_text("assert True")


def test_tar_ships_only_the_package_and_metadata(tmp_path: pathlib.Path) -> None:
    _seed_tree(tmp_path)
    names = _tree_names(tar_working_tree(tmp_path))
    assert "decnet/agent.py" in names
    assert "decnet/__init__.py" in names
    assert "decnet/templates/base.j2" in names  # package-data ships
    assert "pyproject.toml" in names
    assert "LICENSE" in names
    assert "README.md" in names
    # Nothing outside the allowlist:
    assert not any(n.startswith("decnet_web") for n in names)
    assert not any(n.startswith("tests") for n in names)


def test_tar_never_ships_secrets_or_db_or_churn(tmp_path: pathlib.Path) -> None:
    # The whole point of the include-list: these existed at the root and the
    # bundle must not carry a single one of them.
    _seed_tree(tmp_path)
    names = _tree_names(tar_working_tree(tmp_path))
    for forbidden in (".env.local", ".env", "tls.key", "ca.pem", "decnet.db", "master.log"):
        assert forbidden not in names, f"leaked {forbidden}"
    assert not any("__pycache__" in n or n.endswith(".pyc") for n in names)


def test_secret_nested_under_package_is_still_dropped(tmp_path: pathlib.Path) -> None:
    # Defensive hygiene: even a secret-shaped file *inside* decnet/ is excluded.
    _seed_tree(tmp_path)
    (tmp_path / "decnet" / "worker.key").write_text("oops")
    (tmp_path / "decnet" / ".env.prod").write_text("SECRET=1")
    names = _tree_names(tar_working_tree(tmp_path))
    assert "decnet/worker.key" not in names
    assert "decnet/.env.prod" not in names
    assert "decnet/agent.py" in names  # real source still present


def test_extra_excludes_narrows_within_allowlist(tmp_path: pathlib.Path) -> None:
    _seed_tree(tmp_path)
    names = _tree_names(tar_working_tree(tmp_path, extra_excludes=["decnet/agent.py"]))
    assert "decnet/agent.py" not in names
    assert "decnet/__init__.py" in names


def test_extra_excludes_cannot_widen_beyond_allowlist(tmp_path: pathlib.Path) -> None:
    # Passing a non-allowlisted include via extra_excludes is meaningless —
    # excludes can only remove, never add. decnet_web stays out.
    _seed_tree(tmp_path)
    names = _tree_names(tar_working_tree(tmp_path, extra_excludes=[]))
    assert not any(n.startswith("decnet_web") for n in names)


def test_tar_skips_symlinks(tmp_path: pathlib.Path) -> None:
    (tmp_path / "decnet").mkdir()
    (tmp_path / "decnet" / "real.py").write_text("hi")
    try:
        (tmp_path / "decnet" / "link.py").symlink_to(tmp_path / "decnet" / "real.py")
    except (OSError, NotImplementedError):
        return  # platform doesn't support symlinks — skip
    names = _tree_names(tar_working_tree(tmp_path))
    assert "decnet/real.py" in names
    assert "decnet/link.py" not in names


def test_detect_git_sha_from_ref(tmp_path: pathlib.Path) -> None:
    (tmp_path / ".git" / "refs" / "heads").mkdir(parents=True)
    (tmp_path / ".git" / "refs" / "heads" / "main").write_text("deadbeef" * 5 + "\n")
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    assert detect_git_sha(tmp_path).startswith("deadbeef")


def test_detect_git_sha_detached(tmp_path: pathlib.Path) -> None:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0\n")
    assert detect_git_sha(tmp_path).startswith("f0f0")


def test_detect_git_sha_none_when_not_repo(tmp_path: pathlib.Path) -> None:
    assert detect_git_sha(tmp_path) == ""
