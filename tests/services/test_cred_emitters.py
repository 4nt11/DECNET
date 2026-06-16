# SPDX-License-Identifier: AGPL-3.0-or-later
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
async def test_mqtt_native_shape():
    """MQTT CONNECT — username + password decoded from the wire,
    emitted as principal + secret_b64. Was silently dropped between
    Phase 3 (legacy adapter removed) and the MQTT migration commit."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    await _extract_bounty(repo, _native_log(
        "mqtt", principal="iotuser", password="iotpass",
    ))
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "mqtt"
    assert cred["principal"] == "iotuser"
    assert cred["secret_sha256"] == hashlib.sha256(b"iotpass").hexdigest()


@pytest.mark.asyncio
async def test_postgres_hash_credential():
    """Postgres MD5 challenge-response — plaintext irrecoverable, lands
    as secret_kind=postgres_md5_challenge with the raw hash bytes."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    pw_hash = "md5" + "ab" * 16  # 32 hex chars after the "md5" prefix
    raw = bytes.fromhex("ab" * 16)
    log_data = {
        "decky": "decky-01",
        "service": "postgres",
        "attacker_ip": "10.0.0.5",
        "fields": {
            "username": "postgres",
            "principal": "postgres",
            "pw_hash": pw_hash,
            "secret_kind": "postgres_md5_challenge",
            "secret_printable": pw_hash,
            "secret_b64": base64.b64encode(raw).decode("ascii"),
        },
    }
    await _extract_bounty(repo, log_data)
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "postgres"
    assert cred["secret_kind"] == "postgres_md5_challenge"
    assert cred["secret_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.asyncio
async def test_vnc_hash_credential():
    """VNC DES-encrypted challenge response — same shape, different kind."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    raw = bytes(range(16))
    log_data = {
        "decky": "decky-01",
        "service": "vnc",
        "attacker_ip": "10.0.0.5",
        "fields": {
            "response": raw.hex(),
            "secret_kind": "vnc_des_response",
            "secret_printable": raw.hex(),
            "secret_b64": base64.b64encode(raw).decode("ascii"),
        },
    }
    await _extract_bounty(repo, log_data)
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "vnc"
    assert cred["secret_kind"] == "vnc_des_response"
    assert cred["secret_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.asyncio
async def test_snmp_community_native_shape():
    """SNMP v1/v2c community string lands as secret_kind=snmp_community,
    principal=None (no per-user identity in v1/v2c)."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    raw = b"public"
    log_data = {
        "decky": "decky-01",
        "service": "snmp",
        "attacker_ip": "10.0.0.5",
        "fields": {
            "version": 1,
            "community": "public",
            "secret_kind": "snmp_community",
            "secret_printable": "public",
            "secret_b64": base64.b64encode(raw).decode("ascii"),
        },
    }
    await _extract_bounty(repo, log_data)
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "snmp"
    assert cred["secret_kind"] == "snmp_community"
    assert cred["principal"] is None
    assert cred["secret_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.asyncio
async def test_http_basic_native_shape():
    """HTTP Basic via classify_authorization → principal+plaintext."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    log_data = {
        "decky": "decky-01",
        "service": "http",
        "attacker_ip": "10.0.0.5",
        "fields": {
            "method": "GET",
            "path": "/admin",
            "principal": "admin",
            "secret_kind": "plaintext",
            "secret_printable": "hunter2",
            "secret_b64": base64.b64encode(b"hunter2").decode("ascii"),
        },
    }
    await _extract_bounty(repo, log_data)
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "http"
    assert cred["principal"] == "admin"
    assert cred["secret_kind"] == "plaintext"


@pytest.mark.asyncio
async def test_http_bearer_native_shape():
    """HTTP Bearer — principal=None, secret_kind=http_bearer, opaque."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    token = b"eyJhbGciOiJIUzI1NiJ9.foo.bar"
    log_data = {
        "decky": "decky-01",
        "service": "k8s",
        "attacker_ip": "10.0.0.5",
        "fields": {
            "method": "GET",
            "path": "/api/v1/secrets",
            "principal": None,
            "secret_kind": "http_bearer",
            "secret_printable": token.decode(),
            "secret_b64": base64.b64encode(token).decode("ascii"),
        },
    }
    await _extract_bounty(repo, log_data)
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["secret_kind"] == "http_bearer"
    assert cred["principal"] is None
    assert cred["secret_sha256"] == hashlib.sha256(token).hexdigest()


@pytest.mark.asyncio
async def test_sip_digest_native_shape():
    """SIP Digest via classify_authorization → response hash captured."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    response_hash = "d41d8cd98f00b204e9800998ecf8427e"
    log_data = {
        "decky": "decky-01",
        "service": "sip",
        "attacker_ip": "10.0.0.5",
        "fields": {
            "method": "REGISTER",
            "principal": "alice",
            "secret_kind": "http_digest_md5",
            "secret_printable": response_hash,
            "secret_b64": base64.b64encode(response_hash.encode()).decode("ascii"),
        },
    }
    await _extract_bounty(repo, log_data)
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "sip"
    assert cred["secret_kind"] == "http_digest_md5"
    assert cred["principal"] == "alice"


@pytest.mark.asyncio
async def test_mysql_native_password_hash():
    """MySQL handshake auth-response: 20-byte sha1 chain hash. Plaintext
    irrecoverable; lands as secret_kind=mysql_native_password."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    raw = bytes(range(20))  # arbitrary 20-byte "hash"
    log_data = {
        "decky": "decky-01",
        "service": "mysql",
        "attacker_ip": "10.0.0.5",
        "fields": {
            "username": "root",
            "principal": "root",
            "secret_kind": "mysql_native_password",
            "secret_printable": raw.hex(),
            "secret_b64": base64.b64encode(raw).decode("ascii"),
        },
    }
    await _extract_bounty(repo, log_data)
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "mysql"
    assert cred["secret_kind"] == "mysql_native_password"
    assert cred["principal"] == "root"
    assert cred["secret_sha256"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.asyncio
async def test_mssql_login7_plaintext():
    """MSSQL Login7 password is XOR/nibble-obfuscated but plaintext-
    recoverable. Lands as secret_kind=plaintext after deobfuscation."""
    from decnet.web.ingester import _extract_bounty
    repo = MagicMock(); repo.upsert_credential = AsyncMock()
    log_data = {
        "decky": "decky-01",
        "service": "mssql",
        "attacker_ip": "10.0.0.5",
        "fields": {
            "username": "sa",
            "principal": "sa",
            "secret_kind": "plaintext",
            "secret_printable": "hunter2",
            "secret_b64": base64.b64encode(b"hunter2").decode("ascii"),
        },
    }
    await _extract_bounty(repo, log_data)
    cred = repo.upsert_credential.call_args[0][0]
    assert cred["service"] == "mssql"
    assert cred["principal"] == "sa"
    assert cred["secret_printable"] == "hunter2"


def test_mssql_deobfuscate_roundtrip():
    """Direct unit test of the MSSQL Login7 deobfuscation against a
    handcrafted obfuscated buffer. Exercises the algorithm itself."""
    import importlib.util
    import sys
    from pathlib import Path
    from types import ModuleType
    from unittest.mock import MagicMock
    # Stand up a fake syslog_bridge so the template imports cleanly,
    # then load the mssql module and test the static helper.
    fake = ModuleType("syslog_bridge")
    fake.syslog_line = MagicMock(return_value="")
    fake.write_syslog_file = MagicMock()
    fake.forward_syslog = MagicMock()
    fake.SEVERITY_INFO = 6
    fake.SEVERITY_WARNING = 4
    fake.encode_secret = MagicMock(return_value={"secret_printable": "", "secret_b64": ""})
    fake.classify_authorization = MagicMock(return_value=None)
    sys.modules["syslog_bridge"] = fake
    # Load the real instance_seed so the mssql module's top-level
    # _seed.pick(...) tuple-unpack works. MagicMock returns sentinels
    # that don't satisfy iterable unpacking.
    repo_root = Path(__file__).resolve().parents[2]
    if "instance_seed" not in sys.modules:
        seed_spec = importlib.util.spec_from_file_location(
            "instance_seed", repo_root / "decnet" / "templates" / "instance_seed.py"
        )
        seed_mod = importlib.util.module_from_spec(seed_spec)
        seed_spec.loader.exec_module(seed_mod)
        sys.modules["instance_seed"] = seed_mod
    spec = importlib.util.spec_from_file_location(
        "_mssql_under_test", repo_root / "decnet" / "templates" / "mssql" / "server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    # Build the obfuscated form of "abc": each byte → swap nibbles, XOR 0xa5.
    plain = "abc".encode("utf-16-le")  # 6 bytes
    obfuscated = bytes(
        (((b & 0x0f) << 4) | ((b & 0xf0) >> 4)) ^ 0xa5
        for b in plain
    )
    decoded = mod.MSSQLProtocol._deobfuscate_login7_password(obfuscated)
    assert decoded == "abc"


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
