#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Subscribe to a pattern on the local DECNET bus and print events.

Usage: scripts/bus/sub.py 'topology.>'
       scripts/bus/sub.py 'system.bus.health'
       DECNET_BUS_SOCKET=/tmp/decnet-bus.sock scripts/bus/sub.py 'topology.*.status'
"""
from __future__ import annotations

import asyncio
import os
import sys

from decnet.bus.unix_client import UnixSocketBus


async def main(pattern: str) -> None:
    sock = os.environ.get("DECNET_BUS_SOCKET", "/tmp/decnet-bus.sock")
    client = UnixSocketBus(sock, client_name="scripts-sub")
    await client.connect()
    sub = client.subscribe(pattern)
    print(f"sub: pattern={pattern!r} socket={sock}  (Ctrl-C to stop)", flush=True)
    try:
        async with sub:
            async for ev in sub:
                print(f"{ev.topic}  type={ev.type!r}  payload={ev.payload}", flush=True)
    finally:
        await client.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: sub.py <pattern>", file=sys.stderr)
        sys.exit(2)
    try:
        asyncio.run(main(sys.argv[1]))
    except KeyboardInterrupt:
        pass
