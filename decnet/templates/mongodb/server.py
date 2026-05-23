#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
MongoDBserver.
Implements the MongoDB wire protocol OP_MSG/OP_QUERY handshake. Responds
to isMaster/hello, listDatabases, and authenticate commands. Logs all
received messages as JSON.
"""

import asyncio
import base64
import binascii
import os
import struct
from typing import cast

import instance_seed as _seed
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog


# ─── Minimal BSON walker ──────────────────────────────────────────────────────
# Just enough to extract `saslStart` / `saslContinue` command auth fields.
# Pulls a few BSON type codes; ignores everything else (subdocs returned
# as raw bytes the caller can re-parse if needed). Hand-rolled rather
# than pulling pymongo as a runtime dep — we only need 8 type codes and
# the parser is ~40 LoC.

_BSON_DOUBLE = 0x01
_BSON_STRING = 0x02
_BSON_DOC    = 0x03
_BSON_ARRAY  = 0x04
_BSON_BINARY = 0x05
_BSON_BOOL   = 0x08
_BSON_INT32  = 0x10
_BSON_INT64  = 0x12


def _bson_read(buf: bytes, off: int = 0) -> dict:
    """Read a single BSON document at ``buf[off]``. Returns a dict of
    ``{key: value}``. Lossy on unsupported types (silently skipped).
    Untrusted-input safe: bounds-checked, won't infinite-loop on
    malformed length fields."""
    out: dict = {}
    if off + 4 > len(buf):
        return out
    doc_len = struct.unpack_from("<i", buf, off)[0]
    end = off + doc_len
    if end > len(buf) or doc_len < 5:
        return out
    p = off + 4
    while p < end - 1:  # last byte is the trailing 0x00
        t = buf[p]
        p += 1
        if t == 0:
            break
        # Read NUL-terminated cstring key.
        nul = buf.find(b"\x00", p, end)
        if nul < 0:
            break
        key = buf[p:nul].decode("utf-8", errors="replace")
        p = nul + 1
        if t == _BSON_STRING:
            if p + 4 > end:
                break
            slen = struct.unpack_from("<i", buf, p)[0]
            p += 4
            if p + slen > end or slen < 1:
                break
            out[key] = buf[p:p + slen - 1].decode("utf-8", errors="replace")
            p += slen
        elif t == _BSON_BINARY:
            if p + 5 > end:
                break
            blen = struct.unpack_from("<i", buf, p)[0]
            p += 4
            _subtype = buf[p]
            p += 1
            if p + blen > end or blen < 0:
                break
            out[key] = buf[p:p + blen]  # raw bytes
            p += blen
        elif t == _BSON_INT32:
            if p + 4 > end:
                break
            out[key] = struct.unpack_from("<i", buf, p)[0]
            p += 4
        elif t == _BSON_INT64:
            if p + 8 > end:
                break
            out[key] = struct.unpack_from("<q", buf, p)[0]
            p += 8
        elif t == _BSON_BOOL:
            if p + 1 > end:
                break
            out[key] = buf[p] != 0
            p += 1
        elif t == _BSON_DOUBLE:
            p += 8
        elif t in (_BSON_DOC, _BSON_ARRAY):
            if p + 4 > end:
                break
            sub_len = struct.unpack_from("<i", buf, p)[0]
            if p + sub_len > end:
                break
            p += sub_len
        else:
            # Unsupported type — abort cleanly so we don't misalign.
            break
    return out


def _scram_kv(payload: bytes) -> dict:
    """Parse a SCRAM message into key=value pairs. SCRAM separates by
    commas and uses `name=value` pairs. We strip a leading `n,,` (GS2
    header) when present so the `n=username` shows up directly."""
    s = payload.decode("utf-8", errors="replace")
    if s.startswith("n,,"):
        s = s[3:]
    elif s.startswith("y,,"):
        s = s[3:]
    out: dict = {}
    for part in s.split(","):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v
    return out

NODE_NAME = os.environ.get("NODE_NAME", "mongodb")
SERVICE_NAME   = "mongodb"
LOG_TARGET = os.environ.get("LOG_TARGET", "")
PORT = int(os.environ.get("PORT", "27017"))

# Per-instance (version, maxWireVersion) — paired per real MongoDB release.
# Wire version is locked to major/minor per upstream release notes.
_MONGO_RELEASES = [
    ("4.4.22", 9),
    ("5.0.25", 13),
    ("6.0.5",  17),
    ("6.0.14", 17),
    ("7.0.5",  21),
    ("7.0.8",  21),
    ("7.0.11", 21),
]
_MONGO_VERSION, _MONGO_WIRE = _seed.pick(_MONGO_RELEASES)
_MONGO_SET_NAME = os.environ.get("MONGO_REPL_SET", "")  # empty = standalone


def _new_objectid() -> bytes:
    """12-byte BSON ObjectId — fresh per call."""
    return _seed.fresh_bytes(12)

# Minimal BSON helpers
def _bson_str(key: str, val: str) -> bytes:
    k = key.encode() + b"\x00"
    v = val.encode() + b"\x00"
    return b"\x02" + k + struct.pack("<I", len(v)) + v

def _bson_int32(key: str, val: int) -> bytes:
    return b"\x10" + key.encode() + b"\x00" + struct.pack("<i", val)

def _bson_bool(key: str, val: bool) -> bytes:
    return b"\x08" + key.encode() + b"\x00" + (b"\x01" if val else b"\x00")

def _bson_doc(*fields: bytes) -> bytes:
    body = b"".join(fields) + b"\x00"
    return struct.pack("<I", len(body) + 4) + body

def _op_reply(request_id: int, doc: bytes) -> bytes:
    # OP_REPLY header: total_len(4), req_id(4), response_to(4), opcode(4)=1,
    #                  flags(4), cursor_id(8), starting_from(4), number_returned(4), docs
    header = struct.pack(
        "<iiiiiqii",
        16 + 20 + len(doc),  # total length
        0,                    # request id
        request_id,           # response to
        1,                    # OP_REPLY
        0,                    # flags
        0,                    # cursor id (int64)
        0,                    # starting from
        1,                    # number returned
    )
    return header + doc

def _op_msg(request_id: int, doc: bytes) -> bytes:
    payload = b"\x00" + doc
    flag_bits = struct.pack("<I", 0)
    msg_body = flag_bits + payload
    header = struct.pack("<iiii",
        16 + len(msg_body),
        1,
        request_id,
        2013,
    )
    return header + msg_body

def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


class MongoDBProtocol(asyncio.Protocol):
    _transport: asyncio.Transport | None = None
    _peer: tuple[str, int] | None = None

    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""
        # Per-connection SCRAM state: pinned at saslStart so the
        # subsequent saslContinue's client-proof can carry the username
        # in the emitted credential row.
        self._sasl_username: str | None = None
        self._sasl_mechanism: str | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.Transport, transport)
        self._peer = cast(tuple[str, int], self._transport.get_extra_info("peername", ("?", 0)))
        _log("connect", src=self._peer[0], src_port=self._peer[1])

    def data_received(self, data: bytes) -> None:
        assert self._transport is not None
        self._buf += data
        while len(self._buf) >= 16:
            msg_len = struct.unpack("<I", self._buf[:4])[0]
            if msg_len < 16 or msg_len > 48 * 1024 * 1024:
                self._transport.close()
                self._buf = b""
                return
            if len(self._buf) < msg_len:
                break
            msg = self._buf[:msg_len]
            self._buf = self._buf[msg_len:]
            self._handle_message(msg)

    def _handle_message(self, msg: bytes) -> None:
        assert self._transport is not None
        assert self._peer is not None
        if len(msg) < 16:
            return
        request_id = struct.unpack("<I", msg[4:8])[0]
        opcode = struct.unpack("<I", msg[12:16])[0]
        _log("message", src=self._peer[0], opcode=opcode, length=len(msg))

        # SCRAM cred capture: parse the OP_MSG body BSON looking for
        # saslStart / saslContinue. Each fires its own log event:
        # saslStart pins the username + mechanism; saslContinue emits
        # the credential row with the client-proof as secret_b64.
        if opcode == 2013 and len(msg) >= 21:
            # OP_MSG body: 4 bytes flagBits, then sections. We only
            # parse kind=0 (Body) sections — kind=1 (DocSeq) is for
            # bulk ops that don't carry SCRAM auth.
            p = 20  # 16 hdr + 4 flagBits
            while p < len(msg):
                kind = msg[p]
                p += 1
                if kind == 0:  # Body section
                    if p + 4 > len(msg):
                        break
                    doc_len = struct.unpack_from("<i", msg, p)[0]
                    if p + doc_len > len(msg):
                        break
                    cmd = _bson_read(msg, p)
                    self._handle_command(cmd)
                    p += doc_len
                elif kind == 1:  # DocSeq — skip
                    if p + 4 > len(msg):
                        break
                    seq_len = struct.unpack_from("<i", msg, p)[0]
                    p += seq_len
                else:
                    break

        # Build a generic isMaster-style OK response with this instance's
        # version pair. Fresh topologyVersion on every reply (matches real
        # mongod behavior — clients use this to detect failover).
        fields = [
            _bson_bool("ismaster", True),
            _bson_bool("helloOk", True),
            _bson_int32("maxBsonObjectSize", 16777216),
            _bson_int32("maxMessageSizeBytes", 48000000),
            _bson_int32("maxWriteBatchSize", 100000),
            _bson_int32("maxWireVersion", _MONGO_WIRE),
            _bson_int32("minWireVersion", 0),
            _bson_str("version", _MONGO_VERSION),
            _bson_int32("ok", 1),
        ]
        if _MONGO_SET_NAME:
            fields.insert(1, _bson_str("setName", _MONGO_SET_NAME))
        reply_doc = _bson_doc(*fields)
        if opcode == 2013:  # OP_MSG
            self._transport.write(_op_msg(request_id, reply_doc))
        else:
            self._transport.write(_op_reply(request_id, reply_doc))

    def _handle_command(self, cmd: dict) -> None:
        assert self._peer is not None
        """Parse a single MongoDB command document for SCRAM auth.

        saslStart  — client-first-message in payload. Extract
                     `n=<username>` so the next saslContinue inherits it.
        saslContinue — client-final-message in payload. Extract
                       `p=<base64 client-proof>` and emit a cred row.
        """
        # mongo's command dispatch keys off the FIRST field of the BSON
        # document. We just check key presence since dict ordering in
        # CPython 3.7+ matches insertion order.
        if "saslStart" in cmd:
            mechanism = cmd.get("mechanism")
            payload = cmd.get("payload") or b""
            if isinstance(mechanism, str):
                self._sasl_mechanism = mechanism
            if isinstance(payload, (bytes, bytearray)):
                kv = _scram_kv(bytes(payload))
                self._sasl_username = kv.get("n")
                _log("auth_start", src=self._peer[0],
                     mechanism=mechanism or "?",
                     username=self._sasl_username or "")
            return

        if "saslContinue" in cmd:
            payload = cmd.get("payload") or b""
            if not isinstance(payload, (bytes, bytearray)):
                return
            kv = _scram_kv(bytes(payload))
            proof_b64 = kv.get("p")
            if not proof_b64:
                return
            try:
                proof_raw = base64.b64decode(proof_b64, validate=True)
            except (ValueError, binascii.Error):
                return
            mech = (self._sasl_mechanism or "").upper()
            if "SHA-256" in mech or "SHA256" in mech:
                kind = "scram_sha256"
            elif "SHA-1" in mech or "SHA1" in mech:
                kind = "scram_sha1"
            else:
                kind = "scram_unknown"
            _log("auth", src=self._peer[0],
                 username=self._sasl_username or "",
                 principal=self._sasl_username,
                 mechanism=self._sasl_mechanism or "",
                 secret_kind=kind,
                 secret_printable=proof_b64,
                 secret_b64=base64.b64encode(proof_raw).decode("ascii"))
            return

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"MongoDB server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(MongoDBProtocol, "0.0.0.0", PORT)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
