# SPDX-License-Identifier: AGPL-3.0-or-later
"""Schema invariant tests for ``ttp_tag`` (E.2.1).

Pins the structural contract of :class:`~decnet.web.db.models.ttp.TTPTag`:
the CHECK constraint, the app-layer ``ValueError`` guard, the guard's
ordering relative to ``super().__init__()``, the deterministic UUIDv5
shape of ``uuid``, the ``INSERT OR IGNORE`` no-op, and the JSON
round-trip of ``evidence``. The dual-DB invariant (SQLite + MySQL)
lives in E.2.13 repository tests; here we run on SQLite only,
consistent with the rest of ``tests/ttp/``.
"""
from __future__ import annotations

import ast
import inspect
import re
import uuid as _uuid
from typing import AsyncGenerator

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import SQLModel, select

from decnet.web.db.models.ttp import TTPTag, compute_tag_uuid


_UUID5_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


@pytest.fixture
async def session() -> AsyncGenerator[AsyncSession, None]:
    """In-memory async SQLite, full schema, fresh per test.

    Mirrors the StaticPool pattern from ``tests/api/conftest.py``.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
    await engine.dispose()


def _valid_kwargs(**overrides: object) -> dict[str, object]:
    """Build a minimal valid ``TTPTag`` kwargs dict; let callers tweak."""
    base: dict[str, object] = {
        "uuid": compute_tag_uuid("command", "cmd_1", "R0001", 1, "T1083", None),
        "source_kind": "command",
        "source_id": "cmd_1",
        "attacker_uuid": "att_1",
        "identity_uuid": "id_1",
        "tactic": "TA0007",
        "technique_id": "T1083",
        "confidence": 0.5,
        "rule_id": "R0001",
        "rule_version": 1,
        "evidence": {"matched_tokens": ["find"], "rule_pattern": "find"},
        "attack_release": "enterprise-v15.1",
    }
    base.update(overrides)
    return base


# ── CHECK constraint ────────────────────────────────────────────────


async def test_check_constraint_rejects_both_anchors_null(session: AsyncSession) -> None:
    """Raw INSERT bypassing the ``__init__`` guard hits the DB CHECK."""
    with pytest.raises(IntegrityError):
        await session.execute(
            text(
                "INSERT INTO ttp_tag "
                "(uuid, source_kind, source_id, attacker_uuid, identity_uuid, "
                " tactic, technique_id, confidence, rule_id, rule_version, "
                " evidence, attack_release) "
                "VALUES (:uuid, 'command', 'cmd_x', NULL, NULL, "
                " 'TA0007', 'T1083', 0.5, 'R0001', 1, '{}', 'enterprise-v15.1')"
            ),
            {"uuid": str(_uuid.uuid4())},
        )
        await session.commit()


# ── App-layer ValueError guard ──────────────────────────────────────


def test_app_layer_guard_raises_exact_value_error() -> None:
    """Both anchors NULL → exactly ``ValueError`` (not a subclass, not
    pydantic ``ValidationError``)."""
    with pytest.raises(ValueError) as exc_info:
        TTPTag(**_valid_kwargs(attacker_uuid=None, identity_uuid=None))
    # Pin the exact type so a future "simplify" into a Pydantic
    # field-validator (which raises ``ValidationError`` — a subclass of
    # ``ValueError``) trips the test.
    assert type(exc_info.value) is ValueError


def test_app_layer_guard_message_contains_both_anchor_names() -> None:
    with pytest.raises(ValueError) as exc_info:
        TTPTag(**_valid_kwargs(attacker_uuid=None, identity_uuid=None))
    msg = str(exc_info.value)
    assert "attacker_uuid" in msg
    assert "identity_uuid" in msg


def test_guard_runs_before_super_init() -> None:
    """The ``raise ValueError`` line in ``__init__`` MUST appear before
    the ``super().__init__()`` call. A reorder that fires the guard
    after Pydantic validation would surface the failure as
    ``ValidationError`` and break the contract pinned above.

    SQLModel rebuilds ``__init__`` at class-creation time, so
    ``inspect.getsource(TTPTag.__init__)`` returns the dynamic Pydantic
    wrapper. Parse the source file directly and locate the ``__init__``
    inside the ``TTPTag`` class definition.
    """
    src_path = inspect.getsourcefile(TTPTag)
    assert src_path is not None
    with open(src_path) as fh:
        tree = ast.parse(fh.read())
    cls = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name == "TTPTag"
    )
    func = next(
        n for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == "__init__"
    )

    raise_lineno: int | None = None
    super_lineno: int | None = None
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Raise)
            and isinstance(node.exc, ast.Call)
            and isinstance(node.exc.func, ast.Name)
            and node.exc.func.id == "ValueError"
            and raise_lineno is None
        ):
            raise_lineno = node.lineno
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "__init__"
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name)
            and node.func.value.func.id == "super"
            and super_lineno is None
        ):
            super_lineno = node.lineno

    assert raise_lineno is not None, "no `raise ValueError(...)` found in __init__"
    assert super_lineno is not None, "no `super().__init__(...)` found in __init__"
    assert raise_lineno < super_lineno, (
        f"guard at line {raise_lineno} must precede super().__init__ at "
        f"line {super_lineno}; reordering breaks the ValueError contract."
    )


# ── confidence range guard (impl phase) ─────────────────────────────


async def test_confidence_outside_range_rejected_at_insert(session: AsyncSession) -> None:
    """``confidence`` outside [0.0, 1.0] must be rejected. The contract
    schema currently types it as bare ``float`` without a range
    constraint; the impl phase tightens this. Marker flips when the
    constraint lands."""
    tag = TTPTag(**_valid_kwargs(confidence=1.5))
    session.add(tag)
    with pytest.raises((IntegrityError, ValueError)):
        await session.commit()


# ── INSERT OR IGNORE on duplicate uuid ──────────────────────────────


async def test_insert_or_ignore_on_duplicate_uuid_is_noop(session: AsyncSession) -> None:
    kw = _valid_kwargs()
    session.add(TTPTag(**kw))
    await session.commit()

    # Second row with identical PK via INSERT OR IGNORE — the SQLite
    # idempotency path the worker relies on for replay safety.
    await session.execute(
        text(
            "INSERT OR IGNORE INTO ttp_tag "
            "(uuid, source_kind, source_id, attacker_uuid, identity_uuid, "
            " tactic, technique_id, confidence, rule_id, rule_version, "
            " evidence, attack_release) "
            "VALUES (:uuid, 'command', 'cmd_1', 'att_1', 'id_1', "
            " 'TA0007', 'T1083', 0.9, 'R0001', 1, '{}', 'enterprise-v15.1')"
        ),
        {"uuid": kw["uuid"]},
    )
    await session.commit()

    rows = (await session.execute(select(TTPTag).where(TTPTag.uuid == kw["uuid"]))).all()
    assert len(rows) == 1
    # The original confidence sticks; OR IGNORE did not overwrite.
    assert rows[0][0].confidence == 0.5


# ── UUIDv5 shape ────────────────────────────────────────────────────


def test_compute_tag_uuid_matches_uuidv5_regex() -> None:
    out = compute_tag_uuid("command", "cmd_42", "R0014", 2, "T1083", None)
    assert _UUID5_RE.match(out), (
        f"{out!r} is not a UUIDv5 string — pins 'real RFC-4122 UUID, "
        f"not truncated SHA-256' property at the column level."
    )


# ── evidence JSON round-trip ────────────────────────────────────────


async def test_evidence_round_trips_as_dict(session: AsyncSession) -> None:
    payload: dict[str, object] = {
        "matched_tokens": ["find", "/"],
        "rule_pattern": r"find\s+/",
    }
    tag = TTPTag(**_valid_kwargs(evidence=payload))
    session.add(tag)
    await session.commit()

    fetched = (
        await session.execute(select(TTPTag).where(TTPTag.uuid == tag.uuid))
    ).scalar_one()
    assert isinstance(fetched.evidence, dict)
    assert fetched.evidence == payload
