"""record / list / count / prune orchestrator_emails on a real SQLite repo."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from decnet.web.db.sqlite.repository import SQLiteRepository


@pytest_asyncio.fixture
async def repo(tmp_path):
    r = SQLiteRepository(db_path=str(tmp_path / "decnet.db"))
    await r.initialize()
    yield r
    await r.engine.dispose()


def _row(
    mail="d1",
    thread="thr1",
    msg="<m1@x>",
    sender="john@corp.com",
    recipient="sarah@corp.com",
    subject="Q3 budget",
    success=True,
    in_reply_to=None,
    ts=None,
):
    return {
        "ts": ts or datetime.now(timezone.utc),
        "mail_decky_uuid": mail,
        "thread_id": thread,
        "message_id": msg,
        "in_reply_to": in_reply_to,
        "sender_email": sender,
        "recipient_email": recipient,
        "subject": subject,
        "language": "en",
        "eml_path": f"/var/spool/decnet-emails/{thread}/{msg}.eml",
        "success": success,
        "payload": {"model": "llama3.1"},
    }


@pytest.mark.asyncio
async def test_record_returns_uuid_and_serialises_payload(repo):
    uuid = await repo.record_orchestrator_email(_row())
    assert isinstance(uuid, str) and len(uuid) == 36
    rows = await repo.list_orchestrator_emails()
    assert len(rows) == 1
    # payload is stored as JSON text, list endpoint hands it back as the
    # raw column value — we just verify it round-trips intact.
    assert json.loads(rows[0]["payload"])["model"] == "llama3.1"


@pytest.mark.asyncio
async def test_list_filters_by_thread_and_mail_decky(repo):
    await repo.record_orchestrator_email(_row(thread="t1", msg="<a@x>"))
    await repo.record_orchestrator_email(_row(thread="t2", msg="<b@x>"))
    await repo.record_orchestrator_email(_row(mail="d2", msg="<c@x>"))

    by_thread = await repo.list_orchestrator_emails(thread_id="t1")
    assert {r["message_id"] for r in by_thread} == {"<a@x>"}

    by_mail = await repo.list_orchestrator_emails(mail_decky_uuid="d1")
    assert len(by_mail) == 2

    everything = await repo.list_orchestrator_emails()
    assert len(everything) == 3


@pytest.mark.asyncio
async def test_count_orchestrator_emails(repo):
    for i in range(3):
        await repo.record_orchestrator_email(_row(msg=f"<m{i}@x>"))
    assert await repo.count_orchestrator_emails() == 3
    assert await repo.count_orchestrator_emails(mail_decky_uuid="d1") == 3
    assert await repo.count_orchestrator_emails(mail_decky_uuid="other") == 0


@pytest.mark.asyncio
async def test_thread_lookup_only_returns_pair_threads(repo):
    await repo.record_orchestrator_email(
        _row(sender="john@corp.com", recipient="sarah@corp.com", msg="<a@x>")
    )
    # Reverse direction (Sarah → John) should still match the same pair.
    await repo.record_orchestrator_email(
        _row(sender="sarah@corp.com", recipient="john@corp.com", msg="<b@x>")
    )
    # Unrelated pair must not match.
    await repo.record_orchestrator_email(
        _row(sender="mike@corp.com", recipient="sarah@corp.com", msg="<c@x>")
    )
    threads = await repo.list_orchestrator_email_threads(
        "d1", "john@corp.com", "sarah@corp.com",
    )
    assert {t["message_id"] for t in threads} == {"<a@x>", "<b@x>"}


@pytest.mark.asyncio
async def test_thread_lookup_excludes_failed_rows(repo):
    await repo.record_orchestrator_email(_row(msg="<ok@x>", success=True))
    await repo.record_orchestrator_email(_row(msg="<bad@x>", success=False))
    threads = await repo.list_orchestrator_email_threads(
        "d1", "john@corp.com", "sarah@corp.com",
    )
    assert {t["message_id"] for t in threads} == {"<ok@x>"}


@pytest.mark.asyncio
async def test_prune_caps_per_decky(repo):
    # Insert 5 rows on d1 with strictly-increasing timestamps so the
    # prune's "newest-first keep, drop the rest" deterministically picks
    # the older two.
    base = datetime.now(timezone.utc) - timedelta(hours=10)
    for i in range(5):
        await repo.record_orchestrator_email(
            _row(msg=f"<m{i}@x>", ts=base + timedelta(minutes=i))
        )
    # Cap at 3 — expect 2 deleted.
    deleted = await repo.prune_orchestrator_emails(per_decky_cap=3)
    assert deleted == 2
    remaining = await repo.list_orchestrator_emails()
    assert len(remaining) == 3
    # The three newest survived.
    assert {r["message_id"] for r in remaining} == {"<m2@x>", "<m3@x>", "<m4@x>"}
