# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Unit tests for decnet.privdrop — no actual root required.

We stub os.geteuid / os.chown to simulate root and capture the calls,
so these tests are portable (CI doesn't run as root).
"""
import os

import pytest

from decnet import privdrop


def test_chown_noop_when_not_root(tmp_path, monkeypatch):
    target = tmp_path / "x.log"
    target.write_text("")
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    called = []
    monkeypatch.setattr(os, "chown", lambda *a, **kw: called.append(a))
    privdrop.chown_to_invoking_user(target)
    assert called == []


def test_chown_noop_when_no_sudo_env(tmp_path, monkeypatch):
    target = tmp_path / "x.log"
    target.write_text("")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)

    called = []
    monkeypatch.setattr(os, "chown", lambda *a, **kw: called.append(a))
    privdrop.chown_to_invoking_user(target)
    assert called == []


def test_chown_noop_when_path_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    called = []
    monkeypatch.setattr(os, "chown", lambda *a, **kw: called.append(a))
    privdrop.chown_to_invoking_user(tmp_path / "does-not-exist")
    assert called == []


def test_chown_applies_sudo_ids(tmp_path, monkeypatch):
    target = tmp_path / "x.log"
    target.write_text("")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "4242")
    monkeypatch.setenv("SUDO_GID", "4243")

    seen = {}
    def fake_chown(path, uid, gid):
        seen["path"] = str(path)
        seen["uid"] = uid
        seen["gid"] = gid
    monkeypatch.setattr(os, "chown", fake_chown)

    privdrop.chown_to_invoking_user(target)
    assert seen == {"path": str(target), "uid": 4242, "gid": 4243}


def test_chown_tree_recurses(tmp_path, monkeypatch):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b.log").write_text("")
    (tmp_path / "c.log").write_text("")

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    chowned = []
    monkeypatch.setattr(os, "chown", lambda p, *a: chowned.append(str(p)))

    privdrop.chown_tree_to_invoking_user(tmp_path)
    assert str(tmp_path) in chowned
    assert str(tmp_path / "a") in chowned
    assert str(tmp_path / "a" / "b.log") in chowned
    assert str(tmp_path / "c.log") in chowned


def test_chown_swallows_oserror(tmp_path, monkeypatch):
    """A failed chown (e.g. cross-fs sudo edge case) must not raise."""
    target = tmp_path / "x.log"
    target.write_text("")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1000")
    monkeypatch.setenv("SUDO_GID", "1000")

    def boom(*_a, **_kw):
        raise OSError("EPERM")
    monkeypatch.setattr(os, "chown", boom)

    privdrop.chown_to_invoking_user(target)  # must not raise


def test_chown_rejects_malformed_sudo_ids(tmp_path, monkeypatch):
    target = tmp_path / "x.log"
    target.write_text("")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "not-an-int")
    monkeypatch.setenv("SUDO_GID", "1000")

    called = []
    monkeypatch.setattr(os, "chown", lambda *a, **kw: called.append(a))
    privdrop.chown_to_invoking_user(target)
    assert called == []
