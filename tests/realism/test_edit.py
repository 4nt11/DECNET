"""next_iteration mutators per content class.

Stage 3b — read-modify-write contract: each editor takes a previous
body and returns a plausible next iteration.  Append-only for logs;
small in-place edits for user content.
"""
from __future__ import annotations

import random

import pytest

from decnet.realism.bodies import next_iteration
from decnet.realism.taxonomy import ContentClass


def test_todo_edit_can_flip_an_unchecked_box() -> None:
    prev = "- [ ] rotate keys\n- [ ] review pr\n"
    seen_flip = False
    for seed in range(40):
        new = next_iteration(
            ContentClass.TODO, "admin", prev, rand=random.Random(seed),
        )
        if "[x]" in new and "rotate" in new and "[x] rotate" in new:
            seen_flip = True
        if "[x]" in new and "[x] review" in new:
            seen_flip = True
        if seen_flip:
            break
    assert seen_flip, "no checkbox flip across 40 seeds — mutator broken"


def test_todo_edit_grows_or_holds_line_count() -> None:
    prev = "- [ ] rotate keys\n"
    new = next_iteration(
        ContentClass.TODO, "admin", prev, rand=random.Random(0),
    )
    # Mutators may flip a box (same line count) or append (more lines)
    # — but never shrink the file.
    assert len(new.splitlines()) >= len(prev.splitlines())


def test_log_cron_edit_is_append_only() -> None:
    prev = (
        "Apr 27 09:00:01 hostname CRON[1234]: (root) CMD (run-parts /etc/cron.daily)\n"
    )
    new = next_iteration(
        ContentClass.LOG_CRON, "admin", prev, rand=random.Random(0),
    )
    assert new.startswith(prev.rstrip())
    assert len(new.splitlines()) > len(prev.splitlines())


def test_log_daemon_edit_is_append_only() -> None:
    prev = "Apr 27 09:00:01 hostname systemd[1]: Started Daily apt download activities.\n"
    new = next_iteration(
        ContentClass.LOG_DAEMON, "admin", prev, rand=random.Random(0),
    )
    assert new.startswith(prev.rstrip())


def test_note_edit_grows_the_body() -> None:
    prev = "remember to ping the on-call\n"
    new = next_iteration(
        ContentClass.NOTE, "admin", prev, rand=random.Random(0),
    )
    assert prev in new
    assert len(new) > len(prev)


def test_draft_edit_appends_paragraph() -> None:
    prev = "Hi team,\n\nQuick update.\n"
    new = next_iteration(
        ContentClass.DRAFT, "admin", prev, rand=random.Random(0),
    )
    assert new.startswith(prev.rstrip())
    assert len(new) > len(prev)


def test_script_edit_appends_comment() -> None:
    prev = "#!/usr/bin/env bash\nset -e\necho 'hi'\n"
    new = next_iteration(
        ContentClass.SCRIPT, "admin", prev, rand=random.Random(0),
    )
    assert new.startswith(prev.rstrip())
    # New tail must be a comment (the editor's contract); never a
    # silently-injected new exec line.
    new_tail = new[len(prev.rstrip()):].strip()
    assert new_tail.startswith("#")


@pytest.mark.parametrize("cls", [
    ContentClass.CACHE_TMP, ContentClass.EMAIL,
    ContentClass.CANARY_AWS_CREDS, ContentClass.CANARY_HONEYDOC,
])
def test_unsupported_classes_raise_in_edit(cls: ContentClass) -> None:
    with pytest.raises(KeyError):
        next_iteration(cls, "admin", "anything")
