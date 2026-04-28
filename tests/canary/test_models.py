"""Smoke coverage for the Pydantic request/response shapes + helpers.

The tables themselves are exercised end-to-end in
:mod:`tests.canary.test_repository`; this module only covers the
helpers and request validation that don't go through the DB —
``CanaryTrigger.headers()`` JSON decoding, the
``CanaryTokenCreateRequest`` body shape, and the dump-roundtrip on
the response models.
"""
from __future__ import annotations

import pytest

from decnet.web.db.models import (
    CanaryBlobResponse,
    CanaryTokenCreateRequest,
    CanaryTokenResponse,
    CanaryTrigger,
    CanaryTriggerResponse,
)


def test_create_request_minimal() -> None:
    r = CanaryTokenCreateRequest(
        decky_name="web1",
        kind="http",
        placement_path="/home/admin/.env",
        generator="env_file",
    )
    assert r.blob_uuid is None
    assert r.persona_path_hint is None


def test_create_request_kind_is_constrained() -> None:
    with pytest.raises(ValueError):
        CanaryTokenCreateRequest(
            decky_name="web1", kind="bogus",  # type: ignore[arg-type]
            placement_path="/x", generator="aws_creds",
        )


def test_trigger_headers_decode_valid_json() -> None:
    t = CanaryTrigger(
        token_uuid="t",
        src_ip="1.2.3.4",
        raw_headers='{"user-agent":"curl"}',
    )
    assert t.headers() == {"user-agent": "curl"}


@pytest.mark.parametrize("raw", ["", "not json", "[1,2,3]", "null"])
def test_trigger_headers_falls_back_to_empty(raw: str) -> None:
    t = CanaryTrigger(token_uuid="t", src_ip="1.2.3.4", raw_headers=raw)
    assert t.headers() == {}


def test_response_models_round_trip() -> None:
    # Canonical shapes — proves the field set + types match what the
    # router will hand back. Strings everywhere because the DB layer
    # uses str UUIDs (project convention).
    blob = CanaryBlobResponse(
        uuid="b1", sha256="0" * 64, filename="x.docx",
        content_type="application/octet-stream", size_bytes=1,
        uploaded_by="u1", uploaded_at="2026-04-27T00:00:00Z",  # type: ignore[arg-type]
        token_count=2,
    )
    assert blob.token_count == 2

    tok = CanaryTokenResponse(
        uuid="t1", kind="http", decky_name="web1",
        blob_uuid=None, instrumenter=None, generator="aws_creds",
        placement_path="/a", callback_token="s",
        placed_at="2026-04-27T00:00:00Z",  # type: ignore[arg-type]
        last_triggered_at=None, trigger_count=0,
        created_by="u1", state="planted", last_error=None,
    )
    assert tok.kind == "http"

    trig = CanaryTriggerResponse(
        uuid="x", token_uuid="t1",
        occurred_at="2026-04-27T00:00:00Z",  # type: ignore[arg-type]
        src_ip="1.2.3.4", user_agent=None, request_path=None,
        dns_qname=None, headers={}, attacker_id=None,
    )
    assert trig.src_ip == "1.2.3.4"
