"""E.2.13 — Repository tests for the TTP-tag mixin.

Pins the repo contract from ``development/TTP_TAGGING.md`` §E.2.13:

* Per dual-DB-backend project convention, every test runs against
  BOTH SQLite and MySQL via the :func:`db_backends` fixture in
  :mod:`tests.web.db.conftest`.
* ``insert_tags`` is idempotent across runs (same UUID → no duplicate
  row, no exception, second-run insert count is zero).
* ``list_techniques_by_identity`` projects through
  ``Attacker.identity_id`` correctly when ``attacker_uuid`` is set on
  the tag.
* ``list_techniques_by_identity`` returns identity-rollup tags (with
  ``attacker_uuid IS NULL``) correctly.

Method-signature surface is GREEN today (the mixin is wired into the
repo). Behavioral assertions flipped to PASS at E.3.3.
"""
from __future__ import annotations

import inspect
import uuid as _uuid
from datetime import datetime, timezone

import pytest

from decnet.web.db.models import (
    Attacker,
    AttackerIdentity,
    TTPTag,
)
from decnet.web.db.models.ttp import compute_tag_uuid
from decnet.web.db.repository import BaseRepository
from decnet.web.db.sqlmodel_repo.ttp import TTPMixin


# ── Surface (GREEN today) ───────────────────────────────────────────


def test_mixin_methods_are_async() -> None:
    """All four query methods + ``insert_tags`` are coroutines.

    Catches a refactor that accidentally drops the ``async`` keyword
    on a method body — which would silently break the repo's
    expected awaitable interface.
    """
    for name in (
        "insert_tags",
        "list_techniques_by_identity",
        "list_techniques_by_attacker",
        "list_techniques_by_campaign",
        "list_techniques_by_session",
        "list_distinct_techniques",
    ):
        member = getattr(TTPMixin, name)
        assert inspect.iscoroutinefunction(member), (
            f"TTPMixin.{name} must be `async def`"
        )


async def test_mixin_methods_present_on_repo(
    db_backends: BaseRepository,
) -> None:
    """The repository instance returned by the factory exposes every
    TTPMixin method via composition. Confirms the mixin is wired in
    on both SQLite and MySQL (the dual-backend fixture parametrizes).
    """
    for name in (
        "insert_tags",
        "list_techniques_by_identity",
        "list_techniques_by_attacker",
        "list_techniques_by_campaign",
        "list_techniques_by_session",
        "list_distinct_techniques",
    ):
        assert hasattr(db_backends, name)


# ── Behavior (E.3.3 implementation) ─────────────────────────────────


def _make_tag(
    *,
    source_kind: str = "command",
    source_id: str | None = None,
    rule_id: str = "R0001",
    rule_version: int = 1,
    technique_id: str = "T1110",
    sub_technique_id: str | None = None,
    tactic: str = "TA0006",
    confidence: float = 0.85,
    attacker_uuid: str | None = None,
    identity_uuid: str | None = None,
    session_id: str | None = None,
) -> TTPTag:
    """Build a :class:`TTPTag` with deterministic UUID for tests."""
    sid = source_id or _uuid.uuid4().hex
    tag_uuid = compute_tag_uuid(
        source_kind, sid, rule_id, rule_version,
        technique_id, sub_technique_id,
    )
    return TTPTag(
        uuid=tag_uuid,
        source_kind=source_kind,
        source_id=sid,
        attacker_uuid=attacker_uuid,
        identity_uuid=identity_uuid,
        session_id=session_id,
        tactic=tactic,
        technique_id=technique_id,
        sub_technique_id=sub_technique_id,
        confidence=confidence,
        rule_id=rule_id,
        rule_version=rule_version,
        evidence={"matched_tokens": [], "rule_pattern": ""},
        attack_release="15.1",
    )


async def _insert_identity(repo: BaseRepository, uuid: str) -> None:
    async with repo._session() as session:  # type: ignore[attr-defined]
        session.add(AttackerIdentity(uuid=uuid))
        await session.commit()


async def _insert_attacker(
    repo: BaseRepository, uuid: str, ip: str, identity_uuid: str | None = None,
) -> None:
    now = datetime.now(timezone.utc)
    async with repo._session() as session:  # type: ignore[attr-defined]
        session.add(
            Attacker(
                uuid=uuid,
                ip=ip,
                identity_id=identity_uuid,
                first_seen=now,
                last_seen=now,
            )
        )
        await session.commit()


async def test_insert_tags_idempotent_across_runs(
    db_backends: BaseRepository,
) -> None:
    """Running ``insert_tags`` twice on the same row set inserts on
    the first call and no-ops on the second (returned count is 0).
    """
    identity_uuid = _uuid.uuid4().hex
    await _insert_identity(db_backends, identity_uuid)
    rows = [_make_tag(identity_uuid=identity_uuid) for _ in range(3)]
    # Force unique source_ids so the three rows have distinct UUIDs.
    rows = [
        _make_tag(identity_uuid=identity_uuid, source_id=f"src-{i}")
        for i in range(3)
    ]

    inserted_first = await db_backends.insert_tags(rows)
    assert inserted_first == 3

    inserted_second = await db_backends.insert_tags(rows)
    assert inserted_second == 0


async def test_list_by_identity_projects_through_attacker(
    db_backends: BaseRepository,
) -> None:
    """A tag with ``attacker_uuid`` set (and ``identity_uuid`` NULL)
    appears in the per-Identity rollup for the attacker's identity,
    via the ``Attacker.identity_id`` foreign key projection.
    """
    identity_uuid = _uuid.uuid4().hex
    attacker_uuid = _uuid.uuid4().hex
    await _insert_identity(db_backends, identity_uuid)
    await _insert_attacker(
        db_backends, attacker_uuid, "10.0.0.1", identity_uuid,
    )
    tag = _make_tag(attacker_uuid=attacker_uuid, identity_uuid=None)
    await db_backends.insert_tags([tag])

    rows = await db_backends.list_techniques_by_identity(identity_uuid)
    assert len(rows) == 1
    assert rows[0].technique_id == "T1110"
    assert rows[0].count == 1


async def test_list_by_identity_includes_rollup_tags(
    db_backends: BaseRepository,
) -> None:
    """Tags with ``attacker_uuid IS NULL`` and ``identity_uuid`` set
    (the identity-lifter rollup case) appear in the per-Identity
    listing — they belong to the Identity, not any single IP.
    """
    identity_uuid = _uuid.uuid4().hex
    await _insert_identity(db_backends, identity_uuid)
    rollup_tag = _make_tag(
        identity_uuid=identity_uuid,
        attacker_uuid=None,
        rule_id="R_IDENTITY_ROLLUP",
        technique_id="T1078",
    )
    await db_backends.insert_tags([rollup_tag])

    rows = await db_backends.list_techniques_by_identity(identity_uuid)
    techs = {r.technique_id for r in rows}
    assert "T1078" in techs


async def test_list_by_attacker_excludes_rollup_tags(
    db_backends: BaseRepository,
) -> None:
    """Per-Attacker rollup is filtered on ``attacker_uuid``; tags
    with ``attacker_uuid IS NULL`` (identity rollups) are deliberately
    excluded.
    """
    identity_uuid = _uuid.uuid4().hex
    attacker_uuid = _uuid.uuid4().hex
    await _insert_identity(db_backends, identity_uuid)
    await _insert_attacker(
        db_backends, attacker_uuid, "10.0.0.2", identity_uuid,
    )
    direct = _make_tag(
        attacker_uuid=attacker_uuid,
        identity_uuid=identity_uuid,
        technique_id="T1059",
    )
    rollup = _make_tag(
        identity_uuid=identity_uuid,
        attacker_uuid=None,
        rule_id="R_IDENTITY_ROLLUP",
        technique_id="T1078",
    )
    await db_backends.insert_tags([direct, rollup])

    rows = await db_backends.list_techniques_by_attacker(attacker_uuid)
    techs = {r.technique_id for r in rows}
    assert "T1059" in techs
    assert "T1078" not in techs
