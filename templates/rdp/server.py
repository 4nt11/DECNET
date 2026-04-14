#!/usr/bin/env python3
"""
Minimal RDP server using Twisted.
Listens on port 3389, logs connection attempts and any credentials sent
in the initial RDP negotiation request. Forwards events as JSON to
LOG_TARGET if set.
"""

import os

from twisted.internet import protocol, reactor
from twisted.python import log as twisted_log
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "WORKSTATION")
SERVICE_NAME   = "rdp"
LOG_TARGET = os.environ.get("LOG_TARGET", "")




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


class RDPServerProtocol(protocol.Protocol):
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


class RDPServerFactory(protocol.ServerFactory):
    protocol = RDPServerProtocol


if __name__ == "__main__":
    twisted_log.startLoggingWithObserver(lambda e: None, setStdout=False)
    _log("startup", msg=f"RDP server starting as {NODE_NAME} on port 3389")
    reactor.listenTCP(3389, RDPServerFactory())
    reactor.run()
