#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Publish a single event to the local DECNET bus.

Usage: scripts/bus/pub.py <topic> [json-payload] [--type EVENT_TYPE]
Examples:
    scripts/bus/pub.py topology.abc.status '{"state": "active"}'
    scripts/bus/pub.py topology.abc.mutation.applied '{"id": 1}' --type applied
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os

from decnet.bus.unix_client import UnixSocketBus


async def main(topic: str, payload: dict, event_type: str) -> None:
    sock = os.environ.get("DECNET_BUS_SOCKET", "/tmp/decnet-bus.sock")
    client = UnixSocketBus(sock, client_name="scripts-pub")
    await client.connect()
    try:
        await client.publish(topic, payload, event_type=event_type)
        print(f"pub: {topic}  type={event_type!r}  payload={payload}")
    finally:
        await client.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("topic")
    ap.add_argument("payload", nargs="?", default="{}", help="JSON object (default {})")
    ap.add_argument("--type", dest="event_type", default="", help="optional event_type tag")
    args = ap.parse_args()

    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"pub: payload is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        raise SystemExit("pub: payload must be a JSON object")

    asyncio.run(main(args.topic, payload, args.event_type))
