# SPDX-License-Identifier: AGPL-3.0-or-later
"""GET /api/v1/ttp/tags/by-{scope}/{uuid}/{technique_id}.

Pins the operator inspector endpoint that surfaces the rule engine's
reasoning. Each row carries the persisted ``evidence`` JSON, the
firing ``rule_id`` / ``rule_version``, and the ``source_kind`` /
``source_id`` so the UI can answer "what made the engine flag this
technique?".
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx
import pytest

from decnet.web.db.models import TTPTag
from decnet.web.dependencies import repo as _repo

from .conftest import TAG_DETAILS, hdr


def _make_tag(
    *,
    attacker_uuid: str = "att-1",
    technique_id: str = "T1059",
    sub_technique_id: str | None = None,
    rule_id: str = "R0014",
    evidence: dict[str, Any] | None = None,
    source_id: str = "src-1",
) -> TTPTag:
    return TTPTag(
        uuid=f"tag-{rule_id}-{technique_id}-{source_id}",
        source_kind="command",
        source_id=source_id,
        attacker_uuid=attacker_uuid,
        identity_uuid=None,
        session_id=None,
        decky_id=None,
        tactic="TA0006",
        technique_id=technique_id,
        sub_technique_id=sub_technique_id,
        confidence=0.95,
        rule_id=rule_id,
        rule_version=1,
        evidence=evidence or {"command_text": "cat /etc/shadow"},
        attack_release="v15.1",
        created_at=datetime.now(tz=timezone.utc),
    )


@pytest.mark.asyncio
async def test_tag_details_returns_evidence_for_attacker_scope(
    client: httpx.AsyncClient, auth_token: str, ) -> None:
    tags = [_make_tag(rule_id="R0014", source_id=f"cmd-{i}") for i in range(3)]
    await _repo.insert_tags(tags)

    path = TAG_DETAILS.format(
        scope="attacker", uuid="att-1", technique_id="T1059",
    )
    res = await client.get(path, headers=hdr(auth_token))
    assert res.status_code == 200, res.text
    body: list[dict[str, Any]] = res.json()
    assert len(body) == 3
    row = body[0]
    # The evidence dict must round-trip — that's the whole point of
    # the inspector.
    assert row["evidence"]["command_text"] == "cat /etc/shadow"
    assert row["rule_id"] == "R0014"
    assert row["technique_id"] == "T1059"
    assert row["source_kind"] == "command"
    assert "source_id" in row
    assert "created_at" in row


@pytest.mark.asyncio
async def test_tag_details_filters_by_sub_technique(
    client: httpx.AsyncClient, auth_token: str, ) -> None:
    await _repo.insert_tags([
        _make_tag(rule_id="R0014", source_id="a", sub_technique_id="T1059.001"),
        _make_tag(rule_id="R0014", source_id="b", sub_technique_id="T1059.004"),
    ])
    path = TAG_DETAILS.format(
        scope="attacker", uuid="att-1", technique_id="T1059",
    )
    res = await client.get(
        path + "?sub_technique_id=T1059.004",
        headers=hdr(auth_token),
    )
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 1
    assert body[0]["sub_technique_id"] == "T1059.004"


@pytest.mark.asyncio
async def test_tag_details_unknown_scope_400(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    res = await client.get(
        TAG_DETAILS.format(scope="bogus", uuid="att-1", technique_id="T1059"),
        headers=hdr(auth_token),
    )
    # Pydantic Literal validation rejects this at body-parse time,
    # which surfaces as 422 in FastAPI's default config; either 4xx
    # is fine for the contract — we just want non-2xx.
    assert 400 <= res.status_code < 500


@pytest.mark.asyncio
async def test_tag_details_requires_jwt(
    client: httpx.AsyncClient,
) -> None:
    path = TAG_DETAILS.format(
        scope="attacker", uuid="att-1", technique_id="T1059",
    )
    res = await client.get(path)
    assert res.status_code == 401, res.text


@pytest.mark.asyncio
async def test_tag_details_empty_when_no_tags(
    client: httpx.AsyncClient, auth_token: str,
) -> None:
    path = TAG_DETAILS.format(
        scope="attacker", uuid="never-existed", technique_id="T9999",
    )
    res = await client.get(path, headers=hdr(auth_token))
    assert res.status_code == 200
    assert res.json() == []
