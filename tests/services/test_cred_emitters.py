"""Per-service credential-emitter integration tests.

Each test simulates the SD-block a migrated emitter produces, hands it
to the ingester, and asserts the resulting Credential row carries the
universal shape (principal + secret_sha256 + secret_b64 + outcome).

Closes the silent-loss bug for Redis (no username) and LDAP (dn-keyed)
by exercising the full ingester native-shape path for each.
"""
from __future__ import annotations

import base64
import hashlib
from unittest.mock import AsyncMock, MagicMock

import pytest


def _native_log(service: str, *, principal: str | None, password: str,
                outcome: str | None = None, extra: dict | None = None) -> dict:
    """Build a parsed-log dict in the shape `_extract_bounty` consumes,
    matching what a migrated emitter writes to the wire."""
    raw = password.encode("utf-8", errors="replace")
    fields: dict[str, str] = {
        "secret_b64": base64.b64encode(raw).decode("ascii"),
        "secret_printable": "".join(
            chr(b) if 0x20 <= b < 0x7f else "?" for b in raw
        ),
    }
    if principal is not None:
        fields["principal"] = principal
    if outcome is not None:
        fields["outcome"] = outcome
    if extra:
        fields.update(extra)
    return {
        "decky": "decky-01",
        "service": service,
        "attacker_ip": "10.0.0.5",
        "fields": fields,
    }


@pytest.mark.asyncio
async def test_ftp_native_shape():
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    await _extract_bounty(repo, _native_log(
        "ftp", principal="anonymous", password="test@example.com",
    ))
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "ftp"
    assert cred["principal"] == "anonymous"
    assert cred["secret_sha256"] == hashlib.sha256(b"test@example.com").hexdigest()


@pytest.mark.asyncio
async def test_pop3_outcome_mapped():
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    await _extract_bounty(repo, _native_log(
        "pop3", principal="alice", password="hunter2", outcome="failure",
    ))
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "pop3"
    assert cred["outcome"] == "failure"


@pytest.mark.asyncio
async def test_imap_native_shape():
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    await _extract_bounty(repo, _native_log(
        "imap", principal="bob", password="letmein", outcome="success",
    ))
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["principal"] == "bob"
    assert cred["outcome"] == "success"


@pytest.mark.asyncio
async def test_smtp_auth_native_shape():
    """SMTP AUTH PLAIN/LOGIN — principal=SASL username."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    await _extract_bounty(repo, _native_log(
        "smtp", principal="postmaster@acme.com", password="abc123",
    ))
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "smtp"
    assert cred["principal"] == "postmaster@acme.com"


@pytest.mark.asyncio
async def test_smtp_mail_from_is_not_a_credential():
    """`event_type=mail_from` must NOT trigger a credential write —
    even if the SD-block carries a `domain` field, no `secret_b64`
    means the native branch never fires and the legacy branch needs
    a `password` it'll never see for this event."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    repo.add_bounty = AsyncMock()
    log_data = {
        "decky": "decky-01",
        "service": "smtp",
        "attacker_ip": "10.0.0.5",
        "fields": {
            "value": "<spoof@evil.com>",
            "mail_from": "spoof@evil.com",
            "domain": "evil.com",
        },
    }
    await _extract_bounty(repo, log_data)
    repo.upsert_credential.assert_not_awaited()


@pytest.mark.asyncio
async def test_redis_principal_none_lands():
    """Redis legacy AUTH `<password>` — no username, principal stays
    None. This was silently dropped by the legacy adapter pre-migration."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    await _extract_bounty(repo, _native_log(
        "redis", principal=None, password="hunter2",
    ))
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "redis"
    assert cred["principal"] is None
    assert cred["secret_sha256"] == hashlib.sha256(b"hunter2").hexdigest()


@pytest.mark.asyncio
async def test_redis_acl_two_arg_principal_present():
    """Redis 6+ `AUTH <user> <pw>` — principal carries the ACL user."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    await _extract_bounty(repo, _native_log(
        "redis", principal="default", password="hunter2",
    ))
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["principal"] == "default"


@pytest.mark.asyncio
async def test_ldap_principal_is_dn():
    """LDAP bind — the DN itself is the principal."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    await _extract_bounty(repo, _native_log(
        "ldap", principal="cn=admin,dc=acme,dc=com", password="rootpw",
    ))
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "ldap"
    assert cred["principal"] == "cn=admin,dc=acme,dc=com"


@pytest.mark.asyncio
async def test_lossless_b64_survives_nonprintable_password():
    """Even when secret_printable is sanitized, secret_b64 still decodes
    to the original bytes — the cross-service reuse hash matches across
    sanitized and non-sanitized representations."""
    from decnet.web.ingester import _extract_bounty
    raw = b"\x1b[31mbad\xff\x00trail"
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    log_data = {
        "decky": "decky-01",
        "service": "ftp",
        "attacker_ip": "10.0.0.5",
        "fields": {
            "principal": "user",
            "secret_printable": "?[31mbad??trail",
            "secret_b64": base64.b64encode(raw).decode("ascii"),
        },
    }
    await _extract_bounty(repo, log_data)
    cred = repo.upsert_credential.call_args[0][0]
    assert base64.b64decode(cred["secret_b64"]) == raw
    assert cred["secret_sha256"] == hashlib.sha256(raw).hexdigest()
