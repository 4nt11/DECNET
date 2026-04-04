#!/usr/bin/env python3
"""
MongoDBserver.
Implements the MongoDB wire protocol OP_MSG/OP_QUERY handshake. Responds
to isMaster/hello, listDatabases, and authenticate commands. Logs all
received messages as JSON.
"""

import asyncio
import json
import os
import socket
import struct
from datetime import datetime, timezone

NODE_NAME = os.environ.get("NODE_NAME", "mongodb")
LOG_TARGET = os.environ.get("LOG_TARGET", "")

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
        "<iiiiiqqii",
        16 + 20 + len(doc),  # total length
        0,                    # request id
        request_id,           # response to
        1,                    # OP_REPLY
        0,                    # flags
        0,                    # cursor id
        0,                    # starting from
        1,                    # number returned
    )
    return header + doc


def _forward(event: dict) -> None:
    if not LOG_TARGET:
        return
    try:
        host, port = LOG_TARGET.rsplit(":", 1)
        with socket.create_connection((host, int(port)), timeout=3) as s:
            s.sendall((json.dumps(event) + "\n").encode())
    except Exception:
        pass


def _log(event_type: str, **kwargs) -> None:
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "service": "mongodb",
        "host": NODE_NAME,
        "event": event_type,
        **kwargs,
    }
    print(json.dumps(event), flush=True)
    _forward(event)


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

        # Build a generic isMaster-style OK response
        reply_doc = _bson_doc(
            _bson_bool("ismaster", True),
            _bson_int32("maxWireVersion", 17),
            _bson_int32("minWireVersion", 0),
            _bson_str("version", "6.0.5"),
            _bson_int32("ok", 1),
        )
        self._transport.write(_op_reply(request_id, reply_doc))

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"MongoDB server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(MongoDBProtocol, "0.0.0.0", 27017)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
