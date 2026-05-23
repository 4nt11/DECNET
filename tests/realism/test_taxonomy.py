# SPDX-License-Identifier: AGPL-3.0-or-later
"""Coverage for :mod:`decnet.realism.taxonomy`.

The enum values are persisted on ``synthetic_files.content_class`` and
flow through bus topics — renaming a member is a schema change, so the
stable-list test pins the wire format.  ``Plan`` invariants (frozen,
edit requires previous_body) are tested too because the planner relies
on construction-time validation rather than a separate validator pass.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from decnet.realism.taxonomy import ContentClass, Plan


def test_content_class_values_are_stable() -> None:
    # If anyone renames or reorders, the assertion explodes — the
    # enum is wire-visible (synthetic_files.content_class column,
    # bus event payloads) so changes need a schema bump elsewhere.
    assert {c.value for c in ContentClass} == {
        "note", "todo", "draft", "script",
        "log_cron", "log_daemon", "cache_tmp",
        "email",
        "canary_aws_creds", "canary_env_file", "canary_git_config",
        "canary_ssh_key", "canary_honeydoc", "canary_honeydoc_docx",
        "canary_honeydoc_pdf", "canary_mysql_dump",
        "canary_fingerprint_html", "canary_fingerprint_svg",
    }


@pytest.mark.parametrize("name", ["NOTE", "TODO", "DRAFT", "SCRIPT"])
def test_user_classes_classified(name: str) -> None:
    cls = ContentClass[name]
    assert cls.is_user_class()
    assert not cls.is_system_class()
    assert not cls.is_canary()


@pytest.mark.parametrize("name", ["LOG_CRON", "LOG_DAEMON", "CACHE_TMP"])
def test_system_classes_classified(name: str) -> None:
    cls = ContentClass[name]
    assert cls.is_system_class()
    assert not cls.is_user_class()
    assert not cls.is_canary()


def test_canary_members_all_classified() -> None:
    canaries = [c for c in ContentClass if c.value.startswith("canary_")]
    assert canaries, "expected at least one canary content_class"
    for c in canaries:
        assert c.is_canary()
        assert not c.is_user_class()
        assert not c.is_system_class()


def test_email_is_neither_user_nor_system_nor_canary() -> None:
    # Email lives on its own track — same content engine but a
    # different driver and a different table. Classification helpers
    # must not falsely group it into file-class buckets.
    assert ContentClass.EMAIL.value == "email"
    assert not ContentClass.EMAIL.is_user_class()
    assert not ContentClass.EMAIL.is_system_class()
    assert not ContentClass.EMAIL.is_canary()


def _plan(**kw):
    defaults = dict(
        decky_uuid="d-1",
        decky_name="alpha",
        persona="admin",
        content_class=ContentClass.NOTE,
        action="create",
        target_path="/home/admin/notes.txt",
        mtime=datetime(2026, 4, 25, 11, 30, tzinfo=timezone.utc),
        body_hint="todo: rotate keys",
    )
    defaults.update(kw)
    return Plan(**defaults)


def test_plan_is_frozen() -> None:
    p = _plan()
    with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
        p.persona = "ubuntu"  # type: ignore[misc]


def test_edit_plan_requires_previous_body() -> None:
    with pytest.raises(ValueError, match="previous_body"):
        _plan(action="edit", previous_body=None)


def test_edit_plan_with_previous_body_succeeds() -> None:
    p = _plan(action="edit", previous_body="- [ ] rotate keys\n")
    assert p.action == "edit"
    assert p.previous_body == "- [ ] rotate keys\n"


def test_create_plan_does_not_need_previous_body() -> None:
    p = _plan(action="create", previous_body=None)
    assert p.action == "create"
    assert p.previous_body is None
