# SPDX-License-Identifier: AGPL-3.0-or-later
"""Filename realism contracts.

The pre-realism orchestrator emitted ``notes-1777315854.txt`` —
unix-epoch suffix, instant tell.  This file pins the anti-regression:
no namer is allowed to drop a raw decimal timestamp into a filename.
"""
from __future__ import annotations

import re
import secrets

import pytest

from decnet.realism.naming import make_path
from decnet.realism.taxonomy import ContentClass


_USER_CLASSES = (
    ContentClass.NOTE,
    ContentClass.TODO,
    ContentClass.DRAFT,
    ContentClass.SCRIPT,
)
_SYSTEM_CLASSES = (
    ContentClass.LOG_CRON,
    ContentClass.LOG_DAEMON,
    ContentClass.CACHE_TMP,
)


@pytest.mark.parametrize("cls", _USER_CLASSES)
def test_user_class_paths_live_under_persona_home(cls: ContentClass) -> None:
    p = make_path(cls, "admin", rand=secrets.SystemRandom())
    assert p.startswith("/home/admin/"), p


@pytest.mark.parametrize("cls", _SYSTEM_CLASSES)
def test_system_class_paths_have_no_epoch_suffix(cls: ContentClass) -> None:
    rng = secrets.SystemRandom()
    for _ in range(20):
        p = make_path(cls, "admin", rand=rng)
        # The realism failure today: filenames carry raw unix epochs.
        # 8+ consecutive digits in the basename is the tell.
        basename = p.rsplit("/", 1)[-1]
        assert not re.search(r"\d{8,}", basename), (
            f"epoch-shaped suffix found in {p!r}"
        )


def test_log_cron_uses_logrotate_skeleton() -> None:
    seen: set[str] = set()
    rng = secrets.SystemRandom()
    for _ in range(40):
        seen.add(make_path(ContentClass.LOG_CRON, "admin", rand=rng))
    # Real cron only ever writes a fixed set of names; anything outside
    # the logrotate cycle is a realism bug.
    expected = {"/var/log/cron.log", "/var/log/cron.log.1", "/var/log/cron.log.2.gz"}
    assert seen <= expected
    # And we should see at least the canonical name across 40 trials.
    assert "/var/log/cron.log" in seen


def test_cache_tmp_uses_mkstemp_shape() -> None:
    p = make_path(ContentClass.CACHE_TMP, "admin")
    assert re.match(r"^/tmp/\.cache-[a-z0-9]{6}$", p), p


@pytest.mark.parametrize(
    "cls",
    [c for c in ContentClass if c.value.startswith("canary_")],
)
def test_canary_classes_raise_in_naming(cls: ContentClass) -> None:
    with pytest.raises(NotImplementedError, match="canary"):
        make_path(cls, "admin")


def test_email_class_raises_in_naming() -> None:
    with pytest.raises(NotImplementedError, match="email"):
        make_path(ContentClass.EMAIL, "admin")


def test_persona_with_spaces_normalises_to_login() -> None:
    # "John Smith" → "johnsmith" is a plausible login, so the namer
    # collapses spaces rather than falling back. This pins that
    # behaviour against a future overcorrection.
    p = make_path(ContentClass.NOTE, "John Smith")
    assert p.startswith("/home/johnsmith/")


def test_persona_with_punctuation_falls_back_to_user_home() -> None:
    # A persona name with punctuation (or non-ASCII letters) can't
    # cleanly become a username; the namer must fall back to
    # /home/user rather than leak weird chars onto the filesystem.
    p = make_path(ContentClass.NOTE, "C-3PO!")
    assert p.startswith("/home/user/")
