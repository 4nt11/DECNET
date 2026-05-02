"""Shared helpers for TTP API contract tests (E.2.8).

The base ``tests/api/conftest.py`` already provides ``client``,
``auth_token`` (admin role) and ``viewer_token`` (viewer role). This
module adds TTP-specific path constants + a small ``_hdr`` helper so
each test file stays focused on the one endpoint it covers.
"""
from __future__ import annotations


_BASE = "/api/v1/ttp"


def hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ─── Endpoint paths ──────────────────────────────────────────────────────────

# Read endpoints — every entry must round-trip 401 without a JWT and
# 200 with one. Documented in TTP_TAGGING.md "API surface".
TECHNIQUES = f"{_BASE}/techniques"
BY_IDENTITY = _BASE + "/by-identity/{identity_uuid}"
BY_ATTACKER = _BASE + "/by-attacker/{attacker_uuid}"
BY_CAMPAIGN = _BASE + "/by-campaign/{campaign_uuid}"
BY_SESSION = _BASE + "/by-session/{session_id}"
RULES = f"{_BASE}/rules"
TAG_DETAILS = _BASE + "/tags/by-{scope}/{uuid}/{technique_id}"
NAVIGATOR = f"{_BASE}/export/navigator"
NAVIGATOR_IDENTITY = _BASE + "/export/navigator/identity/{uuid}"

# Mutation endpoints — admin-only.
RULE_STATE = _BASE + "/rules/{rule_id}/state"
