#!/usr/bin/env python3
"""
FTP honeypot using Twisted's FTP server infrastructure.
Accepts any credentials, logs all commands and file requests,
forwards events as JSON to LOG_TARGET if set.
"""

import json
import os
import socket
import sys
from datetime import datetime, timezone

from twisted.internet import defer, protocol, reactor
from twisted.protocols.ftp import FTP, FTPFactory
from twisted.python import log as twisted_log

HONEYPOT_NAME = os.environ.get("HONEYPOT_NAME", "ftpserver")
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
        "service": "ftp",
        "host": HONEYPOT_NAME,
        "event": event_type,
        **kwargs,
    }
    print(json.dumps(event), flush=True)
    _forward(event)


class HoneypotFTP(FTP):
    def connectionMade(self):
        peer = self.transport.getPeer()
        _log("connection", src_ip=peer.host, src_port=peer.port)
        super().connectionMade()

    def ftp_USER(self, username):
        self._honeypot_user = username
        _log("user", username=username)
        return super().ftp_USER(username)

    def ftp_PASS(self, password):
        _log("auth_attempt", username=getattr(self, "_honeypot_user", "?"), password=password)
        # Accept everything — we're a honeypot
        self.state = self.AUTHED
        self._user = getattr(self, "_honeypot_user", "anonymous")
        return defer.succeed((230, "Login successful."))

    def ftp_RETR(self, path):
        _log("download_attempt", path=path)
        self.sendLine(b"550 File unavailable.")
        return defer.succeed(None)

    def connectionLost(self, reason):
        peer = self.transport.getPeer()
        _log("disconnect", src_ip=peer.host, src_port=peer.port)
        super().connectionLost(reason)


class HoneypotFTPFactory(FTPFactory):
    protocol = HoneypotFTP


if __name__ == "__main__":
    twisted_log.startLogging(sys.stdout)
    _log("startup", msg=f"FTP honeypot starting as {HONEYPOT_NAME} on port 21")
    reactor.listenTCP(21, HoneypotFTPFactory())
    reactor.run()
