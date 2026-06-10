# SPDX-License-Identifier: AGPL-3.0-or-later
"""Credential model + repo tests — upsert, dedup, cross-service reuse."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from decnet.web.db.factory import get_repository
from decnet.web.db.models import Credential


@pytest.fixture
async def repo(tmp_path: Path):
    r = get_repository(db_path=str(tmp_path / "creds.db"))
    await r.initialize()
    return r


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@pytest.mark.anyio
async def test_upsert_inserts_then_dedups(repo) -> None:
    """Same dedup tuple twice → one row, attempt_count=2."""
    payload = {
        "attacker_ip": "10.0.0.5",
        "decky_name": "decky-01",
        "service": "ssh",
        "principal": "root",
        "secret_sha256": _sha256("hunter2"),
        "secret_b64": "aHVudGVyMg==",
        "secret_printable": "hunter2",
        "fields": {"user": "root"},
    }
    rid_a = await repo.upsert_credential(payload)
    rid_b = await repo.upsert_credential(payload)
    assert rid_a == rid_b
    rows = await repo.get_credentials()
    assert len(rows) == 1
    assert rows[0]["attempt_count"] == 2
    assert rows[0]["fields"] == {"user": "root"}  # preserved


@pytest.mark.anyio
async def test_different_principal_creates_new_row(repo) -> None:
    base = {
        "attacker_ip": "10.0.0.5",
        "decky_name": "decky-01",
        "service": "ssh",
        "secret_sha256": _sha256("hunter2"),
        "secret_b64": "aHVudGVyMg==",
        "secret_printable": "hunter2",
        "fields": {},
    }
    await repo.upsert_credential({**base, "principal": "root"})
    await repo.upsert_credential({**base, "principal": "admin"})
    rows = await repo.get_credentials()
    assert len(rows) == 2


@pytest.mark.anyio
async def test_null_principal_dedups_independently(repo) -> None:
    """principal=None and principal='root' are different keys."""
    base = {
        "attacker_ip": "10.0.0.5",
        "decky_name": "decky-01",
        "service": "ssh",
        "secret_sha256": _sha256("hunter2"),
        "secret_b64": "aHVudGVyMg==",
        "secret_printable": "hunter2",
        "fields": {},
    }
    await repo.upsert_credential({**base, "principal": None})
    await repo.upsert_credential({**base, "principal": None})  # dedupes
    await repo.upsert_credential({**base, "principal": "root"})
    rows = await repo.get_credentials()
    assert len(rows) == 2
    null_row = next(r for r in rows if r["principal"] is None)
    assert null_row["attempt_count"] == 2


@pytest.mark.anyio
async def test_cross_service_reuse_query(repo) -> None:
    """Same secret across SSH + FTP + SMTP → reuse query returns all three."""
    secret = "hunter2"
    sha = _sha256(secret)
    services = [
        ("ssh",  "decky-01", "root"),
        ("ftp",  "decky-02", "anonymous"),
        ("smtp", "decky-03", "acme.com"),
    ]
    for svc, decky, principal in services:
        await repo.upsert_credential({
            "attacker_ip": "10.0.0.5",
            "decky_name": decky,
            "service": svc,
            "principal": principal,
            "secret_sha256": sha,
            "secret_b64": "aHVudGVyMg==",
            "secret_printable": secret,
            "fields": {},
        })
    reuse = await repo.get_credential_attempts_for_secret(sha)
    assert {r["service"] for r in reuse} == {"ssh", "ftp", "smtp"}


@pytest.mark.anyio
async def test_get_credentials_for_attacker(repo) -> None:
    base = {
        "decky_name": "decky-01",
        "service": "ssh",
        "principal": "root",
        "secret_sha256": _sha256("hunter2"),
        "secret_b64": "aHVudGVyMg==",
        "secret_printable": "hunter2",
        "fields": {},
    }
    await repo.upsert_credential({**base, "attacker_ip": "10.0.0.5"})
    await repo.upsert_credential({**base, "attacker_ip": "10.0.0.6"})
    rows = await repo.get_credentials_for_attacker("10.0.0.5")
    assert len(rows) == 1
    assert rows[0]["attacker_ip"] == "10.0.0.5"


@pytest.mark.anyio
async def test_secret_kind_dedups_independently(repo) -> None:
    """Same sha256, same principal — different secret_kind = different row.

    Two rows with the same content-addressable hash but different kinds
    represent fundamentally different credentials (e.g. a plaintext
    password that happens to hash to the same value as a Postgres
    md5 challenge response is statistically impossible but semantically
    distinct anyway). Dedup must respect the kind boundary."""
    base = {
        "attacker_ip": "10.0.0.5",
        "decky_name": "decky-01",
        "service": "ssh",
        "principal": "root",
        "secret_sha256": _sha256("hunter2"),
        "secret_b64": "aHVudGVyMg==",
        "fields": {},
    }
    await repo.upsert_credential({**base, "secret_kind": "plaintext"})
    await repo.upsert_credential({**base, "secret_kind": "postgres_md5_challenge"})
    rows = await repo.get_credentials()
    assert len(rows) == 2
    kinds = {r["secret_kind"] for r in rows}
    assert kinds == {"plaintext", "postgres_md5_challenge"}


@pytest.mark.anyio
async def test_filters(repo) -> None:
    base_secret = _sha256("a")
    await repo.upsert_credential({
        "attacker_ip": "10.0.0.5", "decky_name": "decky-01", "service": "ssh",
        "principal": "root", "secret_sha256": base_secret,
        "secret_printable": "a", "fields": {},
    })
    await repo.upsert_credential({
        "attacker_ip": "10.0.0.5", "decky_name": "decky-01", "service": "ftp",
        "principal": "root", "secret_sha256": base_secret,
        "secret_printable": "a", "fields": {},
    })
    rows = await repo.get_credentials(service="ssh")
    assert len(rows) == 1 and rows[0]["service"] == "ssh"
    assert await repo.get_total_credentials(service="ssh") == 1
    assert await repo.get_total_credentials() == 2


@pytest.mark.anyio
async def test_concurrent_upsert_hits_integrity_retry_branch(
    repo, monkeypatch
) -> None:
    """BUG-12 regression: deterministically exercise the IntegrityError
    retry branch in ``upsert_credential``.

    The prior asyncio.gather test proved nothing — aiosqlite serializes
    both calls through one worker thread, so the second's dedup SELECT
    runs only AFTER the first commits and takes the 'existing is not None'
    fast path. The except-IntegrityError handler NEVER executed; the test
    passed with or without the fix.

    Here we force the race deterministically: the first upsert creates the
    row normally. For the second upsert we monkeypatch the module-level
    ``select`` so its FIRST call (the dedup SELECT) yields a statement that
    matches NOTHING — simulating two callers who both saw 'not found'. The
    second upsert then attempts an INSERT that hits the UNIQUE constraint
    → IntegrityError → rollback → re-SELECT (a fresh, un-poisoned ``select``
    call) finds the winner row → returns its id + increments attempt_count.

    Red-before/green-after: if the ``except IntegrityError`` handler is
    removed, the IntegrityError propagates out of the second upsert and
    this test fails (raises instead of returning a matching id).
    """
    from decnet.web.db.sqlmodel_repo.credentials import _core

    payload = {
        "attacker_ip": "10.0.0.99",
        "decky_name": "decky-concurrent",
        "service": "ssh",
        "principal": "root",
        "secret_sha256": _sha256("racepassword"),
        "secret_b64": "cmFjZXBhc3N3b3Jk",
        "secret_printable": "racepassword",
        "fields": {},
    }

    # First upsert: lands the row normally.
    id_a = await repo.upsert_credential(payload)

    # Poison ONLY the first select() call of the next upsert so the dedup
    # SELECT matches nothing (the simulated race). All later select() calls
    # — including the post-IntegrityError re-SELECT — behave normally.
    real_select = _core.select
    calls = {"n": 0}

    def _poisoned_select(*args, **kwargs):
        stmt = real_select(*args, **kwargs)
        calls["n"] += 1
        if calls["n"] == 1:
            # Append an always-false predicate so the dedup SELECT returns
            # None even though the row exists → forces the INSERT path.
            stmt = stmt.where(Credential.id == -1)
        return stmt

    monkeypatch.setattr(_core, "select", _poisoned_select)

    # Second upsert: dedup SELECT misses → INSERT → IntegrityError → retry.
    id_b = await repo.upsert_credential(payload)

    monkeypatch.undo()

    assert id_a == id_b, "retry branch must return the existing winner's id"
    rows = await repo.get_credentials()
    assert len(rows) == 1, f"expected 1 row, got {len(rows)} (duplicate inserts)"
    assert rows[0]["attempt_count"] == 2, (
        "retry branch must increment attempt_count on the winner row"
    )


@pytest.mark.anyio
async def test_none_and_empty_principal_canonicalize_to_one_row(repo) -> None:
    """BUG-12 canonicalization: principal=None and principal='' canonicalize
    to the SAME principal_key ('') and, with an otherwise-identical dedup
    tuple, must dedup to ONE row — not crash on the UNIQUE constraint.

    Before the fix the dedup SELECT distinguished None from '' (it branched
    on ``is_(None)`` vs ``== principal``) while the constraint keyed on
    principal_key='' for both → the second upsert's SELECT missed, the
    INSERT collided, and the re-SELECT used the wrong (mismatched) filter
    → re-raise / crash. Now SELECT and constraint agree on principal_key.
    """
    base = {
        "attacker_ip": "10.0.0.7",
        "decky_name": "decky-canon",
        "service": "ssh",
        "secret_sha256": _sha256("hunter2"),
        "secret_b64": "aHVudGVyMg==",
        "secret_printable": "hunter2",
        "fields": {},
    }
    id_none = await repo.upsert_credential({**base, "principal": None})
    id_empty = await repo.upsert_credential({**base, "principal": ""})
    assert id_none == id_empty, "None and '' must dedup to the same row"
    rows = await repo.get_credentials()
    assert len(rows) == 1, f"expected 1 row, got {len(rows)}"
    assert rows[0]["attempt_count"] == 2
