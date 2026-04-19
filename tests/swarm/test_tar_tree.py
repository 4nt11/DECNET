"""tar_working_tree: exclude filter, tarball validity, git SHA detection."""
from __future__ import annotations

import io
import pathlib
import tarfile

from decnet.swarm.tar_tree import detect_git_sha, tar_working_tree


def _tree_names(data: bytes) -> set[str]:
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        return {m.name for m in tar.getmembers()}


def test_tar_excludes_default_patterns(tmp_path: pathlib.Path) -> None:
    (tmp_path / "decnet").mkdir()
    (tmp_path / "decnet" / "keep.py").write_text("x = 1")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "pyvenv.cfg").write_text("junk")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (tmp_path / "decnet" / "__pycache__").mkdir()
    (tmp_path / "decnet" / "__pycache__" / "keep.cpython-311.pyc").write_text("bytecode")
    (tmp_path / "wiki-checkout").mkdir()
    (tmp_path / "wiki-checkout" / "Home.md").write_text("# wiki")
    (tmp_path / "run.db").write_text("sqlite")
    (tmp_path / "master.log").write_text("log")

    data = tar_working_tree(tmp_path)
    names = _tree_names(data)
    assert "decnet/keep.py" in names
    assert all(".venv" not in n for n in names)
    assert all(".git" not in n for n in names)
    assert all("__pycache__" not in n for n in names)
    assert all("wiki-checkout" not in n for n in names)
    assert "run.db" not in names
    assert "master.log" not in names


def test_tar_accepts_extra_excludes(tmp_path: pathlib.Path) -> None:
    (tmp_path / "a.py").write_text("x")
    (tmp_path / "secret.env").write_text("TOKEN=abc")
    data = tar_working_tree(tmp_path, extra_excludes=["secret.env"])
    names = _tree_names(data)
    assert "a.py" in names
    assert "secret.env" not in names


def test_tar_skips_symlinks(tmp_path: pathlib.Path) -> None:
    (tmp_path / "real.txt").write_text("hi")
    try:
        (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    except (OSError, NotImplementedError):
        return  # platform doesn't support symlinks — skip
    names = _tree_names(tar_working_tree(tmp_path))
    assert "real.txt" in names
    assert "link.txt" not in names


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
