#!/usr/bin/env python3
"""
Redisserver.
Implements enough of the RESP protocol to respond to AUTH, INFO, CONFIG GET,
KEYS, and arbitrary commands. Logs every command and argument as JSON.
"""

import asyncio
import os
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME    = os.environ.get("NODE_NAME", "cache-server")
SERVICE_NAME   = "redis"
LOG_TARGET   = os.environ.get("LOG_TARGET", "")
_REDIS_VER   = os.environ.get("REDIS_VERSION", "7.2.7")
_REDIS_OS    = os.environ.get("REDIS_OS", "Linux 5.15.0")

_INFO = (
    f"# Server\n"
    f"redis_version:{_REDIS_VER}\n"
    f"redis_mode:standalone\n"
    f"os:{_REDIS_OS}\n"
    f"arch_bits:64\n"
    f"tcp_port:6379\n"
    f"uptime_in_seconds:864000\n"
    f"connected_clients:1\n"
    f"# Keyspace\n"
).encode()




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


def _bulk(s: str) -> bytes:
    enc = s.encode()
    return f"${len(enc)}\r\n".encode() + enc + b"\r\n"


def _err(msg: str) -> bytes:
    return f"-ERR {msg}\r\n".encode()


class RESPParser:
    """Incremental RESP array parser — returns list of str tokens or None if incomplete."""

    def __init__(self):
        self._buf = b""

    def feed(self, data: bytes):
        self._buf += data
        return self._try_parse()

    def _try_parse(self):
        commands = []
        while self._buf:
            cmd, consumed = self._parse_one(self._buf)
            if cmd is None:
                break
            commands.append(cmd)
            self._buf = self._buf[consumed:]
        return commands

    def _parse_one(self, buf: bytes):
        if not buf:
            return None, 0
        if buf[0:1] == b"*":
            end = buf.find(b"\r\n")
            if end == -1:
                return None, 0
            count = int(buf[1:end])
            pos = end + 2
            parts = []
            for _ in range(count):
                if pos >= len(buf):
                    return None, 0
                if buf[pos:pos + 1] != b"$":
                    return None, 0
                end2 = buf.find(b"\r\n", pos)
                if end2 == -1:
                    return None, 0
                length = int(buf[pos + 1:end2])
                start = end2 + 2
                if start + length + 2 > len(buf):
                    return None, 0
                parts.append(buf[start:start + length].decode(errors="replace"))
                pos = start + length + 2
            return parts, pos
        # Inline command
        end = buf.find(b"\r\n")
        if end == -1:
            end = buf.find(b"\n")
        if end == -1:
            return None, 0
        line = buf[:end].decode(errors="replace").strip()
        return line.split(), end + (2 if buf[end:end + 2] == b"\r\n" else 1)


class RedisProtocol(asyncio.Protocol):
    def __init__(self):
        self._transport = None
        self._peer = None
        self._parser = RESPParser()

    def connection_made(self, transport):
        self._transport = transport
        self._peer = transport.get_extra_info("peername", ("?", 0))
        _log("connect", src=self._peer[0], src_port=self._peer[1])

    def data_received(self, data):
        for cmd in self._parser.feed(data):
            self._handle_command(cmd)

    def _handle_command(self, parts):
        if not parts:
            return
        verb = parts[0].upper()
        args = parts[1:]
        _log("command", src=self._peer[0], cmd=verb, args=args[:8])

        if verb == "AUTH":
            password = args[0] if args else ""
            _log("auth", src=self._peer[0], password=password)
            self._transport.write(b"+OK\r\n")
        elif verb == "INFO":
            self._transport.write(f"${len(_INFO)}\r\n".encode() + _INFO + b"\r\n")
        elif verb == "PING":
            self._transport.write(b"+PONG\r\n")
        elif verb == "CONFIG":
            self._transport.write(b"*0\r\n")
        elif verb == "KEYS":
            self._transport.write(b"*0\r\n")
        elif verb == "QUIT":
            self._transport.write(b"+OK\r\n")
            self._transport.close()
        else:
            self._transport.write(_err("unknown command"))

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"Redis server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(RedisProtocol, "0.0.0.0", 6379)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
