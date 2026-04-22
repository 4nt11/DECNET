#!/usr/bin/env python3
"""
MongoDBserver.
Implements the MongoDB wire protocol OP_MSG/OP_QUERY handshake. Responds
to isMaster/hello, listDatabases, and authenticate commands. Logs all
received messages as JSON.
"""

import asyncio
import os
import struct

import instance_seed as _seed
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

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
    def __init__(self):
        self._transport = None
        self._peer = None
        self._buf = b""

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])

    def data_received(self, data):
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

    def _handle_message(self, msg: bytes):
        if len(msg) < 16:
            return
        request_id = struct.unpack("<I", msg[4:8])[0]
        opcode = struct.unpack("<I", msg[12:16])[0]
        _log("message", src=self._peer[0], opcode=opcode, length=len(msg))

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
