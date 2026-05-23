# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Tests for SMTP victim-domain tracking (SmtpTarget table + profiler ingestion).

Two surfaces under test:
  * Repo upsert / list / aggregate-seen helpers.
  * The profiler's `_extract_smtp_domains` + `_normalize_smtp_domain`
    parsers — pure functions exercised directly without running the
    full worker loop.
"""
from datetime import datetime, timezone

import pytest

from decnet.web.db.factory import get_repository
from decnet.correlation.parser import LogEvent
from decnet.profiler.worker import _extract_smtp_domains, _normalize_smtp_domain


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "smtp_targets.db"))
    await r.initialize()
    return r


def _smtp_event(event_type: str, **fields) -> LogEvent:
    return LogEvent(
        timestamp=datetime.now(timezone.utc),
        decky="decky-01",
        service="smtp",
        event_type=event_type,
        attacker_ip="1.2.3.4",
        fields=fields,
        raw="",
    )


# ── Domain normalization ─────────────────────────────────────────────────────

@pytest.mark.parametrize("raw, expected", [
    ("<john@corp1.com>",       "corp1.com"),
    ("JOHN@CORP1.COM",         "corp1.com"),
    ("<alice@mail.corp.io>",   "mail.corp.io"),
    # Empty / malformed → None
    ("",                       None),
    ("notanemail",             None),
    ("@nouser.com",            None),
    ("user@",                  None),
    # Blocked TLDs
    ("admin@foo.invalid",      None),
    ("test@bar.test",          None),
    ("x@local.example",        None),
    # Punctuation / angle-bracket forms the RCPT parser already validated
    ("RCPT TO:<c@d.com>",      "d.com"),
])
def test_normalize_smtp_domain(raw, expected):
    assert _normalize_smtp_domain(raw) == expected


# ── Event → domain extraction ────────────────────────────────────────────────

def test_extract_from_rcpt_to():
    events = [
        _smtp_event("rcpt_to", value="<bob@target.com>"),
        _smtp_event("rcpt_to", value="<alice@other.com>"),
    ]
    assert _extract_smtp_domains(events) == {"target.com", "other.com"}


def test_extract_from_rcpt_denied():
    events = [_smtp_event("rcpt_denied", value="<carol@corp.net>")]
    assert _extract_smtp_domains(events) == {"corp.net"}


def test_extract_from_message_accepted_splits_recipients():
    """`message_accepted.rcpt_to` is a comma-joined list, not a single addr."""
    events = [_smtp_event(
        "message_accepted",
        rcpt_to="<a@one.com>,<b@two.com>,<c@one.com>",
        mail_from="<spam@evil.com>",
    )]
    assert _extract_smtp_domains(events) == {"one.com", "two.com"}


def test_extract_ignores_non_smtp_events():
    """Identical `value` fields on non-smtp services must not leak in."""
    events = [
        LogEvent(
            timestamp=datetime.now(timezone.utc),
            decky="decky-01", service="ssh", event_type="rcpt_to",
            attacker_ip="1.2.3.4",
            fields={"value": "<x@wrong.com>"}, raw="",
        ),
    ]
    assert _extract_smtp_domains(events) == set()


def test_extract_dedupes_within_batch():
    events = [
        _smtp_event("rcpt_to", value="<a@corp.com>"),
        _smtp_event("rcpt_to", value="<b@corp.com>"),
        _smtp_event("rcpt_to", value="<c@corp.com>"),
    ]
    assert _extract_smtp_domains(events) == {"corp.com"}


# ── Repo: increment + list + seen ────────────────────────────────────────────

@pytest.mark.anyio
async def test_increment_creates_then_bumps(repo):
    await repo.increment_smtp_target("uuid-1", "corp.com")
    rows = await repo.list_smtp_targets("uuid-1")
    assert len(rows) == 1
    assert rows[0]["domain"] == "corp.com"
    assert rows[0]["count"] == 1
    first_seen_1 = rows[0]["first_seen"]

    # Second hit bumps count + last_seen, preserves first_seen.
    await repo.increment_smtp_target("uuid-1", "corp.com")
    rows = await repo.list_smtp_targets("uuid-1")
    assert rows[0]["count"] == 2
    assert rows[0]["first_seen"] == first_seen_1


@pytest.mark.anyio
async def test_increment_isolates_per_attacker(repo):
    await repo.increment_smtp_target("uuid-a", "corp.com")
    await repo.increment_smtp_target("uuid-b", "corp.com")
    assert len(await repo.list_smtp_targets("uuid-a")) == 1
    assert len(await repo.list_smtp_targets("uuid-b")) == 1


@pytest.mark.anyio
async def test_list_orders_by_last_seen_desc(repo):
    await repo.increment_smtp_target("uuid-1", "older.com")
    await repo.increment_smtp_target("uuid-1", "newer.com")
    rows = await repo.list_smtp_targets("uuid-1")
    # Second call (newer.com) has a later last_seen → first row.
    assert [r["domain"] for r in rows] == ["newer.com", "older.com"]


@pytest.mark.anyio
async def test_smtp_target_seen_aggregates_across_attackers(repo):
    await repo.increment_smtp_target("uuid-a", "corp.com")
    await repo.increment_smtp_target("uuid-a", "corp.com")
    await repo.increment_smtp_target("uuid-b", "corp.com")
    agg = await repo.smtp_target_seen("corp.com")
    assert agg["seen"] is True
    assert agg["count"] == 3  # 2 + 1
    assert agg["first_seen"] is not None
    assert agg["last_seen"] is not None


@pytest.mark.anyio
async def test_smtp_target_seen_unknown_domain(repo):
    agg = await repo.smtp_target_seen("never-targeted.org")
    assert agg["seen"] is False
    assert agg["count"] == 0
    assert agg["first_seen"] is None
    assert agg["last_seen"] is None
