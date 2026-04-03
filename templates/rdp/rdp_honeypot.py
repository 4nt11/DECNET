#!/usr/bin/env python3
"""
Minimal RDP honeypot using Twisted.
Listens on port 3389, logs connection attempts and any credentials sent
in the initial RDP negotiation request. Forwards events as JSON to
LOG_TARGET if set.
"""

import json
import os
import socket
import sys
from datetime import datetime, timezone

from twisted.internet import protocol, reactor
from twisted.python import log as twisted_log

HONEYPOT_NAME = os.environ.get("HONEYPOT_NAME", "WORKSTATION")
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
        "service": "rdp",
        "host": HONEYPOT_NAME,
        "event": event_type,
        **kwargs,
    }
    print(json.dumps(event), flush=True)
    _forward(event)


class RDPHoneypotProtocol(protocol.Protocol):
    def connectionMade(self):
        peer = self.transport.getPeer()
        _log("connection", src_ip=peer.host, src_port=peer.port)
        # Send a minimal RDP Connection Confirm PDU to keep clients talking
        # X.224 Connection Confirm: length=0x0e, type=0xd0 (CC), dst=0, src=0, class=0
        self.transport.write(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x00\x00\x00")

    def dataReceived(self, data: bytes):
        peer = self.transport.getPeer()
        _log("data", src_ip=peer.host, src_port=peer.port, bytes=len(data), hex=data[:64].hex())
        # Drop the connection after receiving data — we're just a logger
        self.transport.loseConnection()

    def connectionLost(self, reason):
        peer = self.transport.getPeer()
        _log("disconnect", src_ip=peer.host, src_port=peer.port)


class RDPHoneypotFactory(protocol.ServerFactory):
    protocol = RDPHoneypotProtocol


if __name__ == "__main__":
    twisted_log.startLogging(sys.stdout)
    _log("startup", msg=f"RDP honeypot starting as {HONEYPOT_NAME} on port 3389")
    reactor.listenTCP(3389, RDPHoneypotFactory())
    reactor.run()
