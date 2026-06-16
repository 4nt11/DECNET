# SPDX-License-Identifier: AGPL-3.0-or-later
"""kd_digraph_simhash round-trips through update_identity_fingerprints
and the campaign-clustering projection."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from decnet.web.db.factory import get_repository


@pytest.fixture
async def repo(tmp_path):
    r = get_repository(db_path=str(tmp_path / "kd.db"))
    await r.initialize()
    return r


@pytest.mark.asyncio
async def test_fingerprint_write_and_clustering_read(repo):
    now = datetime.now(timezone.utc)
    await repo.create_attacker_identity({
        "uuid": "id-kd", "first_seen_at": now, "last_seen_at": now,
    })
    raw = bytes.fromhex("deadbeefcafef00d")
    await repo.update_identity_fingerprints("id-kd", kd_digraph_simhash=raw)

    rows = await repo.list_identities_for_clustering()
    row = next(r for r in rows if r["uuid"] == "id-kd")
    assert bytes(row["kd_digraph_simhash"]) == raw


@pytest.mark.asyncio
async def test_fingerprint_overwrite_to_none(repo):
    now = datetime.now(timezone.utc)
    await repo.create_attacker_identity({
        "uuid": "id-kd2", "first_seen_at": now, "last_seen_at": now,
    })
    await repo.update_identity_fingerprints("id-kd2", kd_digraph_simhash=b"\x01" * 8)
    # A later pass with no biometric clears it (full-overwrite contract).
    await repo.update_identity_fingerprints("id-kd2", kd_digraph_simhash=None)
    rows = await repo.list_identities_for_clustering()
    row = next(r for r in rows if r["uuid"] == "id-kd2")
    assert row["kd_digraph_simhash"] is None
