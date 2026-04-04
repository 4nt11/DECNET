#!/usr/bin/env python3
"""
FTP server using Twisted's FTP server infrastructure.
Accepts any credentials, logs all commands and file requests,
forwards events as JSON to LOG_TARGET if set.
"""

import os
import sys

from twisted.internet import defer, reactor
from twisted.protocols.ftp import FTP, FTPFactory
from twisted.python import log as twisted_log
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "ftpserver")
SERVICE_NAME   = "ftp"
LOG_TARGET = os.environ.get("LOG_TARGET", "")




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


class ServerFTP(FTP):
    def connectionMade(self):
        peer = self.transport.getPeer()
        _log("connection", src_ip=peer.host, src_port=peer.port)
        super().connectionMade()

    def ftp_USER(self, username):
        self._server_user = username
        _log("user", username=username)
        return super().ftp_USER(username)

    def ftp_PASS(self, password):
        _log("auth_attempt", username=getattr(self, "_server_user", "?"), password=password)
        # Accept everything — we're a server
        self.state = self.AUTHED
        self._user = getattr(self, "_server_user", "anonymous")
        return defer.succeed((230, "Login successful."))

    def ftp_RETR(self, path):
        _log("download_attempt", path=path)
        self.sendLine(b"550 File unavailable.")
        return defer.succeed(None)

    def connectionLost(self, reason):
        peer = self.transport.getPeer()
        _log("disconnect", src_ip=peer.host, src_port=peer.port)
        super().connectionLost(reason)


class ServerFTPFactory(FTPFactory):
    protocol = ServerFTP


if __name__ == "__main__":
    twisted_log.startLogging(sys.stdout)
    _log("startup", msg=f"FTP server starting as {NODE_NAME} on port 21")
    reactor.listenTCP(21, ServerFTPFactory())
    reactor.run()
