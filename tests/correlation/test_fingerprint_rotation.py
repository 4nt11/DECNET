# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for ``decnet.correlation.fingerprint_rotation``.

Pure library: in-memory SQLite + sync Session + collected callback
calls.  No prober, no bus, no async.  Each test seeds an Attacker row,
calls ``record_fingerprint``, asserts on the returned outcome + the
side-effects (state row, Attacker stamp, callback invocations).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine, select

from decnet.correlation.fingerprint_rotation import (
    record_fingerprint,
    RotationOutcome,
)
from decnet.web.db.models import (
    Attacker,
    AttackerFingerprintState,
)


@pytest.fixture
def engine() -> Engine:
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(eng)
    return eng


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 5, 3, 12, 0, 0, tzinfo=timezone.utc)


def _seed_attacker(session: Session, ip: str = "1.2.3.4") -> Attacker:
    a = Attacker(
        uuid="attacker-uuid-1",
        ip=ip,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    session.add(a)
    session.commit()
    session.refresh(a)
    return a


class _Recorder:
    """Capture (event_type, payload) tuples from publish_fn / syslog_fn."""
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, event_type: str, payload: dict) -> None:
        self.calls.append((event_type, payload))


def test_no_attacker_row_returns_noop(engine, now):
    publish, syslog = _Recorder(), _Recorder()
    with Session(engine) as session:
        outcome = record_fingerprint(
            session,
            attacker_ip="9.9.9.9",
            port=22,
            probe_type="hassh",
            new_hash="abc",
            ts=now,
            publish_fn=publish,
            syslog_fn=syslog,
        )
    assert outcome.kind == "no_attacker_row"
    assert publish.calls == []
    assert syslog.calls == []
    with Session(engine) as session:
        rows = session.exec(select(AttackerFingerprintState)).all()
    assert rows == []


def test_first_sighting_creates_state_row_no_event(engine, now):
    publish, syslog = _Recorder(), _Recorder()
    with Session(engine) as session:
        _seed_attacker(session)
        outcome = record_fingerprint(
            session,
            attacker_ip="1.2.3.4",
            port=22,
            probe_type="hassh",
            new_hash="hash-1",
            ts=now,
            publish_fn=publish,
            syslog_fn=syslog,
        )
    assert outcome.kind == "first_sighting"
    assert outcome.old_hash is None
    assert outcome.new_hash == "hash-1"
    assert outcome.rotation_count == 0
    assert publish.calls == []
    assert syslog.calls == []
    with Session(engine) as session:
        rows = session.exec(select(AttackerFingerprintState)).all()
        assert len(rows) == 1
        assert rows[0].last_hash == "hash-1"
        assert rows[0].rotation_count == 0
        a = session.exec(select(Attacker)).one()
        assert a.rotation_count == 0
        assert a.last_rotation_at is None


def test_unchanged_hash_bumps_last_seen_no_event(engine, now):
    publish, syslog = _Recorder(), _Recorder()
    later = now + timedelta(minutes=10)
    with Session(engine) as session:
        _seed_attacker(session)
        record_fingerprint(
            session,
            attacker_ip="1.2.3.4", port=22, probe_type="hassh",
            new_hash="hash-1", ts=now,
        )
        outcome = record_fingerprint(
            session,
            attacker_ip="1.2.3.4", port=22, probe_type="hassh",
            new_hash="hash-1", ts=later,
            publish_fn=publish, syslog_fn=syslog,
        )
    assert outcome.kind == "unchanged"
    assert publish.calls == []
    assert syslog.calls == []
    with Session(engine) as session:
        row = session.exec(select(AttackerFingerprintState)).one()
        # SQLite strips tzinfo on round-trip; compare naive values.
        assert row.last_seen.replace(tzinfo=timezone.utc) == later
        assert row.rotation_count == 0


def test_rotated_emits_event_and_stamps_attacker(engine, now):
    publish, syslog = _Recorder(), _Recorder()
    later = now + timedelta(hours=1)
    with Session(engine) as session:
        _seed_attacker(session)
        record_fingerprint(
            session,
            attacker_ip="1.2.3.4", port=22, probe_type="hassh",
            new_hash="hash-1", ts=now,
        )
        outcome = record_fingerprint(
            session,
            attacker_ip="1.2.3.4", port=22, probe_type="hassh",
            new_hash="hash-2", ts=later,
            publish_fn=publish, syslog_fn=syslog,
        )

    assert outcome.kind == "rotated"
    assert outcome.old_hash == "hash-1"
    assert outcome.new_hash == "hash-2"
    assert outcome.rotation_count == 1

    assert len(publish.calls) == 1
    assert len(syslog.calls) == 1
    event_type, payload = publish.calls[0]
    assert event_type == "attacker.fingerprint_rotated"
    assert payload["attacker_uuid"] == "attacker-uuid-1"
    assert payload["attacker_ip"] == "1.2.3.4"
    assert payload["port"] == 22
    assert payload["probe_type"] == "hassh"
    assert payload["old_hash"] == "hash-1"
    assert payload["new_hash"] == "hash-2"
    assert payload["rotation_count"] == 1
    assert payload["ts"] == later.isoformat()

    with Session(engine) as session:
        a = session.exec(select(Attacker)).one()
        assert a.rotation_count == 1
        assert a.last_rotation_at is not None
        assert a.last_rotation_at.replace(tzinfo=timezone.utc) == later
        row = session.exec(select(AttackerFingerprintState)).one()
        assert row.last_hash == "hash-2"
        assert row.rotation_count == 1


def test_three_probe_types_independent(engine, now):
    with Session(engine) as session:
        _seed_attacker(session)
        for ptype in ("jarm", "hassh", "tcpfp"):
            record_fingerprint(
                session,
                attacker_ip="1.2.3.4", port=22, probe_type=ptype,
                new_hash=f"{ptype}-1", ts=now,
            )
    with Session(engine) as session:
        rows = session.exec(select(AttackerFingerprintState)).all()
    assert {r.probe_type for r in rows} == {"jarm", "hassh", "tcpfp"}
    assert {r.last_hash for r in rows} == {"jarm-1", "hassh-1", "tcpfp-1"}


def test_two_ports_same_probe_type_independent(engine, now):
    with Session(engine) as session:
        _seed_attacker(session)
        for port in (22, 2222):
            record_fingerprint(
                session,
                attacker_ip="1.2.3.4", port=port, probe_type="hassh",
                new_hash=f"hash-{port}", ts=now,
            )
    with Session(engine) as session:
        rows = session.exec(select(AttackerFingerprintState)).all()
    assert {r.port for r in rows} == {22, 2222}


def test_multiple_rotations_increment_counter(engine, now):
    publish = _Recorder()
    with Session(engine) as session:
        _seed_attacker(session)
        record_fingerprint(
            session,
            attacker_ip="1.2.3.4", port=22, probe_type="hassh",
            new_hash="h1", ts=now, publish_fn=publish,
        )
        record_fingerprint(
            session,
            attacker_ip="1.2.3.4", port=22, probe_type="hassh",
            new_hash="h2", ts=now + timedelta(minutes=5), publish_fn=publish,
        )
        record_fingerprint(
            session,
            attacker_ip="1.2.3.4", port=22, probe_type="hassh",
            new_hash="h3", ts=now + timedelta(minutes=10), publish_fn=publish,
        )
    assert len(publish.calls) == 2  # first call was first_sighting (no event)
    with Session(engine) as session:
        a = session.exec(select(Attacker)).one()
        assert a.rotation_count == 2
        row = session.exec(select(AttackerFingerprintState)).one()
        assert row.rotation_count == 2
        assert row.last_hash == "h3"


def test_emit_after_commit_raising_publish_does_not_lose_row(engine, now) -> None:
    """BUG-9 regression: publish_fn is called AFTER session.commit().

    A raising publish_fn must not roll back / lose the committed rotation
    row.  Before fix, publish was called before commit so a raise in
    publish_fn left the session without a commit and the state row was lost.
    """
    later = now + timedelta(hours=1)

    call_order: list[str] = []

    class _OrderRecorder:
        def __call__(self, event_type: str, payload: dict) -> None:
            call_order.append("emit")
            raise RuntimeError("downstream unavailable")

    publish = _OrderRecorder()

    with Session(engine) as session:
        # Patch session.commit to record ordering.
        original_commit = session.commit

        def _recording_commit() -> None:
            call_order.append("commit")
            original_commit()

        session.commit = _recording_commit  # type: ignore[method-assign]

        _seed_attacker(session)

    with Session(engine) as session:
        original_commit2 = session.commit

        def _recording_commit2() -> None:
            call_order.append("commit")
            original_commit2()

        session.commit = _recording_commit2  # type: ignore[method-assign]

        # first_sighting — no publish yet
        record_fingerprint(
            session,
            attacker_ip="1.2.3.4", port=22, probe_type="hassh",
            new_hash="h1", ts=now,
        )
        call_order.clear()

        # rotation — publish_fn raises after commit
        outcome = record_fingerprint(
            session,
            attacker_ip="1.2.3.4", port=22, probe_type="hassh",
            new_hash="h2", ts=later,
            publish_fn=publish,
        )

    assert outcome.kind == "rotated"
    # commit must come before emit
    assert call_order.index("commit") < call_order.index("emit")

    # The rotation row must be persisted despite publish raising
    with Session(engine) as session:
        row = session.exec(select(AttackerFingerprintState)).one()
        assert row.last_hash == "h2"
        assert row.rotation_count == 1
