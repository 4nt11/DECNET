# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression test for BUG-6: multi-token JSON-field search collapses all
custom filters to the last value (shared :val bind parameter).

Root cause: ``_apply_filters`` loops over search tokens and for each
JSON-field token calls ``.params(val=val)``. Because every call reuses the
same bind name ``:val``, SQLAlchemy's last ``.params()`` call overwrites all
earlier ones — only the last JSON-field token's value is actually bound.

The fix gives each JSON-field token a distinct bind parameter name
(``jval_0``, ``jval_1``, …) so every token value survives.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path: Path):
    r = get_repository(db_path=str(tmp_path / "log_search.db"))
    await r.initialize()
    return r


async def _add_log(repo, **kwargs) -> None:
    base = {
        "raw_line": "test",
        "decky": "decky-01",
        "service": "ssh",
        "event_type": "cmd",
        "attacker_ip": "10.0.0.1",
        "timestamp": "2025-01-01T00:00:00",
        "fields": {},
    }
    base.update(kwargs)
    await repo.add_log(base)


# ── BUG-6 regression ─────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_single_json_field_token_matches(repo) -> None:
    """Baseline: a single JSON-field token filters correctly."""
    await _add_log(repo, fields={"cmd": "ls", "user": "root"})
    await _add_log(repo, fields={"cmd": "rm", "user": "bob"})

    logs = await repo.get_logs(search='cmd:ls')
    assert len(logs) == 1
    assert json.loads(logs[0]["fields"])["cmd"] == "ls"


@pytest.mark.anyio
async def test_two_distinct_json_field_tokens_both_applied(repo) -> None:
    """BUG-6 regression: two JSON-field tokens must BOTH filter.

    Before the fix, only the last token's value was bound. A search for
    ``cmd:ls user:root`` would execute with ``val='root'`` for both
    predicates — rows with ``cmd='ls'`` but ``user='bob'`` would appear
    in the results instead of being filtered out.
    """
    await _add_log(repo, fields={"cmd": "ls", "user": "root"})   # should match
    await _add_log(repo, fields={"cmd": "ls", "user": "bob"})    # cmd matches, user doesn't
    await _add_log(repo, fields={"cmd": "rm", "user": "root"})   # user matches, cmd doesn't
    await _add_log(repo, fields={"cmd": "rm", "user": "bob"})    # neither matches

    logs = await repo.get_logs(search='cmd:ls user:root')
    # Only the first row satisfies both predicates.
    assert len(logs) == 1, (
        f"Expected 1 log matching cmd:ls AND user:root, got {len(logs)}. "
        "BUG-6: shared :val bind param causes last token to overwrite earlier ones."
    )
    fields = json.loads(logs[0]["fields"])
    assert fields["cmd"] == "ls"
    assert fields["user"] == "root"


@pytest.mark.anyio
async def test_three_json_field_tokens_all_applied(repo) -> None:
    """Three JSON-field tokens must all filter independently."""
    await _add_log(repo, fields={"a": "1", "b": "2", "c": "3"})   # full match
    await _add_log(repo, fields={"a": "1", "b": "2", "c": "X"})   # c mismatch
    await _add_log(repo, fields={"a": "1", "b": "X", "c": "3"})   # b mismatch
    await _add_log(repo, fields={"a": "X", "b": "2", "c": "3"})   # a mismatch

    logs = await repo.get_logs(search='a:1 b:2 c:3')
    assert len(logs) == 1
    fields = json.loads(logs[0]["fields"])
    assert fields == {"a": "1", "b": "2", "c": "3"}


@pytest.mark.anyio
async def test_json_field_token_mixed_with_core_field_token(repo) -> None:
    """A JSON-field token combined with a core-field filter both apply."""
    await _add_log(
        repo,
        decky="decky-01",
        fields={"cmd": "whoami"},
    )
    await _add_log(
        repo,
        decky="decky-02",
        fields={"cmd": "whoami"},
    )

    # Only decky-01 row should match.
    logs = await repo.get_logs(search='decky:decky-01 cmd:whoami')
    assert len(logs) == 1
    assert logs[0]["decky"] == "decky-01"
