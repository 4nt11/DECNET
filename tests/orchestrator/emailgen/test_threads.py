# SPDX-License-Identifier: AGPL-3.0-or-later
"""Thread-chain helpers."""
from __future__ import annotations

from decnet.orchestrator.emailgen.threads import (
    ThreadChain,
    new_message_id,
    new_thread_id,
    references_for_reply,
    reply_subject,
)


def test_new_thread_id_is_uuid_string():
    tid = new_thread_id()
    assert len(tid) == 36
    assert tid.count("-") == 4


def test_new_message_id_format_with_domain():
    mid = new_message_id("example.com")
    assert mid.startswith("<") and mid.endswith(">")
    assert "@example.com" in mid


def test_new_message_id_handles_blank_domain():
    mid = new_message_id("   ")
    assert "@localhost" in mid


def test_reply_subject_prepends_re():
    assert reply_subject("Q3 budget") == "Re: Q3 budget"


def test_reply_subject_collapses_existing_re():
    assert reply_subject("Re: Re: Q3 budget") == "Re: Q3 budget"
    assert reply_subject("RE: Q3 budget") == "Re: Q3 budget"


def test_references_for_reply_root_is_empty():
    assert references_for_reply(None) == ""


def test_references_for_reply_appends_parent():
    chain = ThreadChain(
        thread_id="t1",
        parent_message_id="<m2@x>",
        references=("<m1@x>",),
        parent_subject="Re: budget",
    )
    refs = references_for_reply(chain)
    assert refs == "<m1@x> <m2@x>"


def test_references_empty_chain_starts_with_parent_only():
    chain = ThreadChain(
        thread_id="t1",
        parent_message_id="<m1@x>",
        references=(),
        parent_subject="budget",
    )
    assert references_for_reply(chain) == "<m1@x>"
