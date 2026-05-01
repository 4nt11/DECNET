#!/usr/bin/env python3
"""
Redisserver.
Implements enough of the RESP protocol to respond to AUTH, INFO, CONFIG GET,
KEYS, and arbitrary commands. Logs every command and argument as JSON.
"""

import asyncio
import os
from typing import cast

import instance_seed as _seed
from syslog_bridge import (
    encode_secret,
    forward_syslog,
    syslog_line,
    write_syslog_file,
)

NODE_NAME    = os.environ.get("NODE_NAME", "cache-server")
SERVICE_NAME   = "redis"
LOG_TARGET   = os.environ.get("LOG_TARGET", "")
PORT         = int(os.environ.get("PORT", "6379"))

# Per-instance realistic version pick (weighted toward still-supported lines).
_REDIS_VER = os.environ.get("REDIS_VERSION") or _seed.pick_weighted([
    ("7.2.4", 2), ("7.2.5", 3), ("7.2.6", 3), ("7.2.7", 2),
    ("7.0.15", 2), ("7.0.14", 1),
    ("6.2.14", 2), ("6.2.16", 1),
])
# Kernel line matching plausible Debian/Ubuntu LTS minor ranges.
_REDIS_OS = os.environ.get("REDIS_OS") or _seed.pick([
    "Linux 5.15.0-118-generic x86_64",
    "Linux 6.1.0-21-amd64 x86_64",
    "Linux 5.10.0-30-amd64 x86_64",
    "Linux 6.5.0-27-generic x86_64",
])
_RUN_ID = _seed.instance_hex(20, "redis-run")
_PROCESS_ID = _seed.rng.randint(120, 32000)
_TCP_PORT_STR = str(PORT)

# AUTH config: empty REDIS_PASSWORD means "no auth configured" — AUTH returns
# the canonical "Client sent AUTH, but no password is set" error, matching a
# real redis-server with requirepass unset.
_REQUIREPASS = os.environ.get("REDIS_PASSWORD", "")


def _info_block() -> bytes:
    uptime = _seed.uptime_seconds()
    uptime_days = max(1, uptime // 86400)
    # Minimal but plausible subset; real redis INFO has ~150 keys.
    text = (
        "# Server\r\n"
        f"redis_version:{_REDIS_VER}\r\n"
        f"redis_git_sha1:00000000\r\n"
        f"redis_git_dirty:0\r\n"
        f"redis_build_id:{_seed.instance_hex(8, 'redis-build')}\r\n"
        "redis_mode:standalone\r\n"
        f"os:{_REDIS_OS}\r\n"
        "arch_bits:64\r\n"
        f"process_id:{_PROCESS_ID}\r\n"
        f"run_id:{_RUN_ID}\r\n"
        f"tcp_port:{_TCP_PORT_STR}\r\n"
        f"uptime_in_seconds:{uptime}\r\n"
        f"uptime_in_days:{uptime_days}\r\n"
        "hz:10\r\n"
        "# Clients\r\n"
        "connected_clients:1\r\n"
        "maxclients:10000\r\n"
        "# Memory\r\n"
        f"used_memory:{_seed.rng.randint(800_000, 12_000_000)}\r\n"
        "mem_fragmentation_ratio:1.12\r\n"
        "# Stats\r\n"
        f"total_connections_received:{_seed.rng.randint(50, 9000)}\r\n"
        f"total_commands_processed:{_seed.rng.randint(5_000, 2_000_000)}\r\n"
        "# Keyspace\r\n"
    )
    return text.encode()


def _build_fake_store() -> dict[bytes, bytes]:
    """Per-instance plausible cache content. No embedded DECNET-identifying
    strings; keys / values shaped like what real apps leave in redis."""
    n_sessions = _seed.rng.randint(3, 14)
    store: dict[bytes, bytes] = {}
    app_slug = _seed.pick(["api", "web", "worker", "shop", "admin", "cms"])
    env_slug = _seed.pick(["prod", "stage", "live"])
    for i in range(n_sessions):
        sid = _seed.instance_hex(16, f"sess-{i}")
        uid = _seed.rng.randint(1000, 999_999)
        store[f"session:{sid}".encode()] = (
            f'{{"uid":{uid},"exp":{int(_seed.boot_epoch()) + 86400 * 7}}}'
        ).encode()
    for i in range(_seed.rng.randint(2, 6)):
        store[f"cache:{app_slug}:feed:{i}".encode()] = (
            _seed.instance_hex(24, f"feed-{i}").encode()
        )
    store[f"stats:{app_slug}:{env_slug}:requests".encode()] = (
        str(_seed.rng.randint(5_000, 900_000)).encode()
    )
    return store


_FAKE_STORE = _build_fake_store()

# Config presented via CONFIG GET — realistic subset of a default redis.conf.
_CONFIG = {
    "maxmemory": "0",
    "maxmemory-policy": "noeviction",
    "maxclients": "10000",
    "timeout": "0",
    "tcp-keepalive": "300",
    "databases": "16",
    "save": "3600 1 300 100 60 10000",
    "appendonly": "no",
    "loglevel": "notice",
    "dir": "/var/lib/redis",
    "bind": "127.0.0.1 -::1",
    "protected-mode": "yes",
    "supervised": "systemd",
}




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
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


def _config_get(pattern: str) -> bytes:
    """Emulate `CONFIG GET <pattern>` — returns alternating key/value bulks."""
    import fnmatch
    matches = [(k, v) for k, v in _CONFIG.items() if fnmatch.fnmatchcase(k, pattern)]
    out = f"*{len(matches) * 2}\r\n".encode()
    for k, v in matches:
        out += _bulk(k) + _bulk(v)
    return out


class RedisProtocol(asyncio.Protocol):
    _transport: asyncio.Transport | None = None
    _peer: tuple[str, int] | None = None

    def __init__(self):
        self._transport = None
        self._peer = None
        self._parser = RESPParser()
        self._authed = not _REQUIREPASS  # auth satisfied iff no password set

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self._transport = cast(asyncio.Transport, transport)
        self._peer = cast(tuple[str, int], self._transport.get_extra_info("peername", ("?", 0)))
        _log("connect", src=self._peer[0], src_port=self._peer[1])

    def data_received(self, data):
        for cmd in self._parser.feed(data):
            self._handle_command(cmd)

    def _write(self, payload: bytes) -> None:
        """Writes with per-response jitter. Unseeded so two connections to
        the same decky don't get an identical latency fingerprint. Honeypot
        throughput targets are low; a few ms of blocking sleep here is fine
        and avoids the asyncio-task plumbing the synchronous protocol model
        doesn't otherwise need."""
        _seed.jitter_sync(2, 40)
        if self._transport and not self._transport.is_closing():
            self._transport.write(payload)

    def _handle_command(self, parts) -> None:
        assert self._peer is not None
        if not parts:
            return
        verb = parts[0].upper()
        args = parts[1:]
        _log("command", src=self._peer[0], cmd=verb, args=args[:8])

        if verb == "AUTH":
            # Redis 6+ accepts two-arg AUTH (`AUTH <user> <pw>`) for ACL
            # auth; legacy single-arg AUTH is just the password. Capture
            # the username when present so attackers brute-forcing ACLs
            # leave the same trail SSH/FTP do.
            password = args[-1] if args else ""
            _user = args[0] if len(args) >= 2 else None
            _log("auth", src=self._peer[0],
                 principal=_user, **encode_secret(password))
            if not _REQUIREPASS:
                self._write(
                    _err("Client sent AUTH, but no password is set. "
                         "Did you mean AUTH <username> <password>?")
                )
            elif password == _REQUIREPASS:
                self._authed = True
                self._write(b"+OK\r\n")
            else:
                self._write(_err("WRONGPASS invalid username-password pair or user is disabled."))
            return
        if not self._authed:
            self._write(_err("NOAUTH Authentication required."))
            return
        if verb == "INFO":
            info = _info_block()
            self._write(f"${len(info)}\r\n".encode() + info + b"\r\n")
        elif verb == "PING":
            self._write(b"+PONG\r\n")
        elif verb == "CONFIG":
            sub = args[0].upper() if args else ""
            if sub == "GET" and len(args) >= 2:
                self._write(_config_get(args[1]))
            elif sub == "SET":
                self._write(b"+OK\r\n")
            elif sub == "RESETSTAT":
                self._write(b"+OK\r\n")
            else:
                self._write(_err(
                    "Unknown CONFIG subcommand or wrong number of arguments for '"
                    f"{sub.lower() or '?'}'"
                ))
        elif verb == "KEYS":
            pattern = args[0] if args else "*"
            keys = list(_FAKE_STORE.keys())
            if pattern.endswith('*') and pattern != '*':
                prefix = pattern[:-1].encode()
                keys = [k for k in keys if k.startswith(prefix)]
            elif pattern != '*':
                pat = pattern.encode()
                keys = [k for k in keys if k == pat]

            resp = f"*{len(keys)}\r\n".encode() + b"".join(_bulk(k.decode()) for k in keys)
            self._write(resp)
        elif verb == "GET":
            key = args[0].encode() if args else b""
            if key in _FAKE_STORE:
                self._write(_bulk(_FAKE_STORE[key].decode()))
            else:
                self._write(b"$-1\r\n")
        elif verb == "SCAN":
            keys = list(_FAKE_STORE.keys())
            resp = b"*2\r\n$1\r\n0\r\n" + f"*{len(keys)}\r\n".encode() + b"".join(_bulk(k.decode()) for k in keys)
            self._write(resp)
        elif verb == "TYPE":
            self._write(b"+string\r\n")
        elif verb == "TTL":
            self._write(b":-1\r\n")
        elif verb == "DBSIZE":
            self._write(f":{len(_FAKE_STORE)}\r\n".encode())
        elif verb == "COMMAND":
            self._write(b"*0\r\n")
        elif verb == "CLIENT":
            self._write(b"+OK\r\n")
        elif verb == "SELECT":
            self._write(b"+OK\r\n")
        elif verb == "QUIT":
            self._write(b"+OK\r\n")
            if self._transport:
                self._transport.close()
        else:
            self._write(_err(f"unknown command '{verb.lower()}'"))

    def connection_lost(self, exc):
        _log("disconnect", src=self._peer[0] if self._peer else "?")


async def main():
    _log("startup", msg=f"Redis server starting as {NODE_NAME}")
    loop = asyncio.get_running_loop()
    server = await loop.create_server(RedisProtocol, "0.0.0.0", PORT)  # nosec B104
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
