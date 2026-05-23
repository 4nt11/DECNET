# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Schema-only tests for the AttackerIdentity table and the
attackers.identity_id FK.

The identities table ships empty in this PR; the clusterer that
populates it is a separate downstream effort. These tests verify only
that the schema lands correctly:

* the table exists after metadata.create_all()
* attackers.identity_id is nullable and indexed
* the FK references attacker_identities.uuid
* an attacker row may be inserted with identity_id=NULL
* an identity row may be inserted with all clusterer-populated columns NULL

If any of these regress, downstream API/frontend/clusterer work all
stop. See development/IDENTITY_RESOLUTION.md §Schema.
"""
from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect
from sqlmodel import Session

from decnet.web.db.models import Attacker, AttackerIdentity
from decnet.web.db.sqlite.database import get_sync_engine, init_db


@pytest.fixture
def db_path(tmp_path) -> str:
    p = tmp_path / "schema.db"
    init_db(str(p))
    return str(p)


def test_attacker_identities_table_exists(db_path: str) -> None:
    engine = get_sync_engine(db_path)
    inspector = inspect(engine)
    assert "attacker_identities" in inspector.get_table_names()


def test_attackers_identity_id_column_present_and_nullable(db_path: str) -> None:
    engine = get_sync_engine(db_path)
    inspector = inspect(engine)
    columns = {c["name"]: c for c in inspector.get_columns("attackers")}
    assert "identity_id" in columns, "attackers.identity_id column missing"
    assert columns["identity_id"]["nullable"] is True, (
        "attackers.identity_id must be nullable — clusterer hasn't run yet on existing rows"
    )


def test_attackers_identity_id_is_indexed(db_path: str) -> None:
    engine = get_sync_engine(db_path)
    inspector = inspect(engine)
    indexes = inspector.get_indexes("attackers")
    indexed_columns = {col for idx in indexes for col in idx["column_names"]}
    assert "identity_id" in indexed_columns, (
        "attackers.identity_id needs an index for join performance "
        "(IdentityDetail aggregates by identity_id; without an index "
        "every lookup is a full scan)"
    )


def test_attackers_identity_id_fk_targets_attacker_identities(db_path: str) -> None:
    engine = get_sync_engine(db_path)
    inspector = inspect(engine)
    fks = inspector.get_foreign_keys("attackers")
    identity_fks = [
        fk for fk in fks if "identity_id" in fk["constrained_columns"]
    ]
    assert identity_fks, "no FK on attackers.identity_id"
    assert identity_fks[0]["referred_table"] == "attacker_identities"
    assert identity_fks[0]["referred_columns"] == ["uuid"]


def test_identity_schema_version_default_is_1(db_path: str) -> None:
    """
    schema_version is non-negotiable from day one. Federation gossip
    in V2 will share identity vectors across operators; bumping the
    feature definitions without a version field silently poisons
    receivers. Default must be 1 on insert.
    """
    engine = get_sync_engine(db_path)
    with Session(engine) as session:
        identity = AttackerIdentity(uuid=str(uuid.uuid4()))
        session.add(identity)
        session.commit()
        session.refresh(identity)
        assert identity.schema_version == 1


def test_attacker_can_be_inserted_with_null_identity_id(db_path: str) -> None:
    """
    Existing code paths (profiler, correlator) keep upserting attackers
    without setting identity_id. They MUST work unchanged — the
    identity_id column is nullable and remains NULL until the clusterer
    runs.
    """
    engine = get_sync_engine(db_path)
    with Session(engine) as session:
        now = datetime.now(timezone.utc)
        att = Attacker(
            uuid=str(uuid.uuid4()),
            ip="203.0.113.4",
            first_seen=now,
            last_seen=now,
        )
        session.add(att)
        session.commit()
        session.refresh(att)
        assert att.identity_id is None


def test_identity_with_all_clusterer_fields_null(db_path: str) -> None:
    """
    The table ships empty; even when the clusterer eventually inserts
    rows, it may write a row with most fields null (e.g. before
    fingerprint summaries have been computed). Every clusterer-populated
    column must accept NULL.
    """
    engine = get_sync_engine(db_path)
    with Session(engine) as session:
        identity = AttackerIdentity(uuid=str(uuid.uuid4()))
        session.add(identity)
        session.commit()
        session.refresh(identity)
        for field in (
            "campaign_id",
            "first_seen_at",
            "last_seen_at",
            "confidence",
            "ja3_hashes",
            "hassh_hashes",
            "payload_simhashes",
            "c2_endpoints",
            "kd_digraph_simhash",
            "merged_into_uuid",
            "notes",
        ):
            assert getattr(identity, field) is None, (
                f"AttackerIdentity.{field} must default to None — "
                f"the table ships empty pre-clusterer"
            )
        # observation_count is denormalized; defaults to 0 (not NULL).
        assert identity.observation_count == 0


def test_attacker_identity_link_round_trip(db_path: str) -> None:
    """
    End-to-end: insert an identity, link an attacker observation to
    it via identity_id FK, query both sides. Smoke-tests the schema
    works as designed without invoking the production repo layer.
    """
    engine = get_sync_engine(db_path)
    with Session(engine) as session:
        identity = AttackerIdentity(uuid=str(uuid.uuid4()))
        session.add(identity)
        session.commit()

        now = datetime.now(timezone.utc)
        att = Attacker(
            uuid=str(uuid.uuid4()),
            ip="203.0.113.5",
            first_seen=now,
            last_seen=now,
            identity_id=identity.uuid,
        )
        session.add(att)
        session.commit()
        session.refresh(att)
        assert att.identity_id == identity.uuid


def test_identity_id_fk_constraint_blocks_orphans(db_path: str) -> None:
    """
    Inserting an attacker with identity_id pointing at a nonexistent
    identity must fail. The clusterer should never write an orphan
    link; the schema enforces that contract.

    SQLite's PRAGMA foreign_keys is off by default at the connection
    level; we enable it explicitly here so the test reflects the
    contract production code relies on (via the same PRAGMA on its
    connections).
    """
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO attackers (uuid, ip, first_seen, last_seen, "
                "event_count, service_count, decky_count, services, deckies, "
                "is_traversal, bounty_count, credential_count, fingerprints, "
                "commands, updated_at, identity_id) VALUES "
                "(?, ?, ?, ?, 0, 0, 0, '[]', '[]', 0, 0, 0, '[]', '[]', ?, ?)",
                (
                    str(uuid.uuid4()),
                    "203.0.113.6",
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                    "ffffffff-ffff-ffff-ffff-ffffffffffff",  # nonexistent identity
                ),
            )
            conn.commit()
