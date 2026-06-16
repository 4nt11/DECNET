# SPDX-License-Identifier: AGPL-3.0-or-later
"""MongoDB SCRAM credential capture tests.

Exercises the inline BSON walker + SCRAM extractor by handcrafting
saslStart / saslContinue OP_MSG packets and feeding them to the
MongoDBProtocol's data_received(). Asserts that the resulting _log
calls carry the universal credential SD shape.
"""
from __future__ import annotations

import base64
import importlib.util
import struct
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock


def _load_mongodb():
    """Stand up the mongodb template module with stub deps so the test
    can poke its protocol directly."""
    fake = ModuleType("syslog_bridge")
    fake.syslog_line = MagicMock(return_value="")
    fake.write_syslog_file = MagicMock()
    fake.forward_syslog = MagicMock()
    fake.SEVERITY_INFO = 6
    fake.SEVERITY_WARNING = 4
    fake.encode_secret = MagicMock(
        return_value={"secret_printable": "", "secret_b64": ""}
    )
    fake.classify_authorization = MagicMock(return_value=None)
    sys.modules["syslog_bridge"] = fake

    repo_root = Path(__file__).resolve().parents[2]
    if "instance_seed" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "instance_seed", repo_root / "decnet" / "templates" / "instance_seed.py"
        )
        seed_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(seed_mod)
        sys.modules["instance_seed"] = seed_mod

    spec = importlib.util.spec_from_file_location(
        "_mongodb_under_test",
        repo_root / "decnet" / "templates" / "mongodb" / "server.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── BSON encoding helpers (test-only) ────────────────────────────────────────

def _bson_str(key: str, val: str) -> bytes:
    k = key.encode() + b"\x00"
    v = val.encode() + b"\x00"
    return b"\x02" + k + struct.pack("<i", len(v)) + v


def _bson_int32(key: str, val: int) -> bytes:
    return b"\x10" + key.encode() + b"\x00" + struct.pack("<i", val)


def _bson_binary(key: str, val: bytes) -> bytes:
    return (
        b"\x05" + key.encode() + b"\x00"
        + struct.pack("<i", len(val))
        + b"\x00"  # subtype 0 = generic
        + val
    )


def _bson_doc(*fields: bytes) -> bytes:
    body = b"".join(fields) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def _op_msg(request_id: int, doc: bytes) -> bytes:
    body = b"\x00\x00\x00\x00" + b"\x00" + doc  # flags + kind=0 + body doc
    return struct.pack("<iiii", 16 + len(body), request_id, 0, 2013) + body


# ── Tests ────────────────────────────────────────────────────────────────────

def test_bson_walker_basic_types():
    mod = _load_mongodb()
    doc = _bson_doc(
        _bson_str("greeting", "hello"),
        _bson_int32("answer", 42),
        _bson_binary("blob", b"\x00\x01\xff"),
    )
    parsed = mod._bson_read(doc)
    assert parsed["greeting"] == "hello"
    assert parsed["answer"] == 42
    assert parsed["blob"] == b"\x00\x01\xff"


def test_bson_walker_malformed_safe():
    mod = _load_mongodb()
    # Garbage bytes — must not raise or loop.
    assert mod._bson_read(b"\x05\x00\x00\x00\x00") == {}  # 5-byte empty doc
    assert mod._bson_read(b"\x00" * 4) == {}  # too short
    assert mod._bson_read(b"\xff" * 64) == {}  # invalid length


def test_scram_kv_strips_gs2_header():
    mod = _load_mongodb()
    payload = b"n,,n=alice,r=clientNonce123"
    parsed = mod._scram_kv(payload)
    assert parsed["n"] == "alice"
    assert parsed["r"] == "clientNonce123"


def test_sasl_start_pins_username():
    """saslStart sets per-connection username + mechanism state for the
    subsequent saslContinue to inherit."""
    mod = _load_mongodb()
    proto = mod.MongoDBProtocol()
    proto._transport = MagicMock()
    proto._peer = ("10.0.0.5", 51234)

    payload = b"n,,n=alice,r=cnonce"
    cmd = _bson_doc(
        _bson_int32("saslStart", 1),
        _bson_str("$db", "admin"),
        _bson_str("mechanism", "SCRAM-SHA-256"),
        _bson_binary("payload", payload),
    )
    pkt = _op_msg(request_id=1, doc=cmd)
    proto.data_received(pkt)

    assert proto._sasl_username == "alice"
    assert proto._sasl_mechanism == "SCRAM-SHA-256"


def _capture_log(mod):
    """Replace mod._log with a list-collector; returns (captured, restore)."""
    captured: list = []
    orig = mod._log
    mod._log = lambda et, severity=6, **kw: captured.append((et, kw))
    return captured, lambda: setattr(mod, "_log", orig)


def test_sasl_continue_emits_cred():
    """saslContinue → emits a _log call with secret_kind="scram_sha256"
    and secret_b64 = b64(decoded_proof). The _sasl_username pinned in
    the prior saslStart attaches as principal."""
    mod = _load_mongodb()
    proto = mod.MongoDBProtocol()
    proto._transport = MagicMock()
    proto._peer = ("10.0.0.5", 51234)
    proto._sasl_username = "alice"
    proto._sasl_mechanism = "SCRAM-SHA-256"

    proof = b"\xab" * 32
    proof_b64 = base64.b64encode(proof).decode("ascii")
    final_payload = f"c=biws,r=combined,p={proof_b64}".encode()
    cmd = _bson_doc(
        _bson_int32("saslContinue", 1),
        _bson_str("$db", "admin"),
        _bson_int32("conversationId", 1),
        _bson_binary("payload", final_payload),
    )
    pkt = _op_msg(request_id=2, doc=cmd)

    captured, restore = _capture_log(mod)
    try:
        proto.data_received(pkt)
    finally:
        restore()

    auth_events = [e for e in captured if e[0] == "auth"]
    assert len(auth_events) == 1
    fields = auth_events[0][1]
    assert fields["secret_kind"] == "scram_sha256"
    assert fields["principal"] == "alice"
    assert fields["username"] == "alice"
    assert base64.b64decode(fields["secret_b64"]) == proof


def test_sasl_continue_unknown_mechanism():
    """When mechanism doesn't advertise SHA-{1,256}, fall back to
    scram_unknown so the row still lands."""
    mod = _load_mongodb()
    proto = mod.MongoDBProtocol()
    proto._transport = MagicMock()
    proto._peer = ("10.0.0.5", 0)
    proto._sasl_username = "bob"
    proto._sasl_mechanism = "PLAIN"

    final_payload = (
        b"c=biws,r=x,p="
        + base64.b64encode(b"proof").decode("ascii").encode()
    )
    cmd = _bson_doc(
        _bson_int32("saslContinue", 1),
        _bson_str("$db", "admin"),
        _bson_binary("payload", final_payload),
    )
    pkt = _op_msg(request_id=3, doc=cmd)

    captured, restore = _capture_log(mod)
    try:
        proto.data_received(pkt)
    finally:
        restore()

    auth = [e for e in captured if e[0] == "auth"]
    assert len(auth) == 1
    assert auth[0][1]["secret_kind"] == "scram_unknown"
