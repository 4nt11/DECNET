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
repo). Behavioral assertions xfail-gated behind E.3.3 — the empty
bodies raise ``NotImplementedError``.
"""
from __future__ import annotations

import inspect

import pytest

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


# ── Behavior (xfail until E.3.3) ────────────────────────────────────


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.3 — insert_tags idempotency lands with the "
    "repository implementation",
)
async def test_insert_tags_idempotent_across_runs(
    db_backends: BaseRepository,
) -> None:
    """Running ``insert_tags`` twice on the same row set inserts on
    the first call and no-ops on the second (returned count is 0).

    Today the body raises ``NotImplementedError`` so the assertion
    xfails. Flips at E.3.3.
    """
    pytest.fail("insert_tags not yet implemented")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.3 — list_techniques_by_identity projection "
    "through Attacker.identity_id lands with the repository impl",
)
async def test_list_by_identity_projects_through_attacker(
    db_backends: BaseRepository,
) -> None:
    """A tag with ``attacker_uuid`` set (and ``identity_uuid`` NULL)
    appears in the per-Identity rollup for the attacker's identity,
    via the ``Attacker.identity_id`` foreign key projection.
    """
    pytest.fail("list_techniques_by_identity not yet implemented")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.3 — identity-rollup tags (NULL attacker_uuid) "
    "land with the repository impl",
)
async def test_list_by_identity_includes_rollup_tags(
    db_backends: BaseRepository,
) -> None:
    """Tags with ``attacker_uuid IS NULL`` and ``identity_uuid`` set
    (the identity-lifter rollup case) appear in the per-Identity
    listing — they belong to the Identity, not any single IP.
    """
    pytest.fail("list_techniques_by_identity not yet implemented")


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.3 — list_techniques_by_attacker excludes "
    "identity-rollup tags by design; lands with the repo impl",
)
async def test_list_by_attacker_excludes_rollup_tags(
    db_backends: BaseRepository,
) -> None:
    """Per-Attacker rollup is filtered on ``attacker_uuid``; tags
    with ``attacker_uuid IS NULL`` (identity rollups) are deliberately
    excluded. Pinned per design doc §E.2.13: "those belong to the
    Identity, not any one IP underneath it."
    """
    pytest.fail("list_techniques_by_attacker not yet implemented")
