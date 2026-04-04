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
from decnet_logging import syslog_line, write_syslog_file, forward_syslog

NODE_NAME = os.environ.get("NODE_NAME", "WORKSTATION")
SERVICE_NAME   = "smb"
LOG_TARGET = os.environ.get("LOG_TARGET", "")




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    print(line, flush=True)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


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
