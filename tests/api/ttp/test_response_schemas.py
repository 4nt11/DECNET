"""E.2.8 — Response-schema stability via golden fixtures.

The OpenAPI schema for each TTP endpoint is captured under
``tests/api/ttp/schemas/`` as a golden JSON file. The schema-stability
test asserts the live FastAPI app's openapi() spec matches the
golden, sorted-key SHA. Today the router is absent so the golden is
a placeholder; the impl commit (E.3.8) updates the golden in the
same diff that lands the routes.

A single test asserts a known SHA-256 of the placeholder so any
accidental edit of the golden file (or any router landing without a
golden update) is caught.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from decnet.web.api import app


_SCHEMAS_DIR = Path(__file__).parent / "schemas"
_PLACEHOLDER = _SCHEMAS_DIR / "endpoints.placeholder.json"


def _sha256_sorted(payload: object) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_placeholder_golden_is_stable() -> None:
    """The placeholder file is a constant. Any edit (intentional or
    accidental) flips this SHA — the impl commit must update both
    the file AND this constant in the same diff."""
    payload = json.loads(_PLACEHOLDER.read_text(encoding="utf-8"))
    assert _sha256_sorted(payload) == (
        "c9e8a7f2d4e65fc5e55b7616670f4ce336e1f3d154e8581f18fd24e334b9ca97"
    )


@pytest.mark.xfail(
    strict=True,
    reason="impl phase E.3.8: TTP router not yet contributing to OpenAPI",
)
def test_openapi_includes_ttp_paths() -> None:
    """Every documented TTP endpoint must appear in the live OpenAPI
    schema once the router lands. Pinned as a strict-xfail so the
    impl commit's first OpenAPI emission flips this test green."""
    spec = app.openapi()
    paths = set(spec.get("paths", {}).keys())
    must_appear = {
        "/api/v1/ttp/techniques",
        "/api/v1/ttp/rules",
        "/api/v1/ttp/export/navigator",
    }
    assert must_appear <= paths
