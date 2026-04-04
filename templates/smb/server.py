#!/usr/bin/env python3
"""
Minimal SMB server using Impacket's SimpleSMBServer.
Logs all connection attempts, optionally forwarding them as JSON to LOG_TARGET.
"""

import json
import os
import socket
from datetime import datetime, timezone

from impacket import smbserver

NODE_NAME = os.environ.get("NODE_NAME", "WORKSTATION")
LOG_TARGET = os.environ.get("LOG_TARGET", "")


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
        "service": "smb",
        "host": NODE_NAME,
        "event": event_type,
        **kwargs,
    }
    print(json.dumps(event), flush=True)
    _forward(event)


if __name__ == "__main__":
    _log("startup", msg=f"SMB server starting as {NODE_NAME}")
    os.makedirs("/tmp/smb_share", exist_ok=True)

    server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=445)
    server.setSMB2Support(True)
    server.setSMBChallenge("")
    server.addShare("SHARE", "/tmp/smb_share", "Shared Documents")
    try:
        server.start()
    except KeyboardInterrupt:
        _log("shutdown")
