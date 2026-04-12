#!/usr/bin/env python3
"""
Entrypoint wrapper for the Conpot ICS/SCADA honeypot.

Launches conpot as a child process and bridges its log output into the
DECNET structured syslog pipeline.  Each line from conpot stdout/stderr
is classified and emitted as an RFC 5424 syslog line so the host-side
collector can ingest it alongside every other service.

Written to be compatible with Python 3.6 (the conpot base image version).
"""
from __future__ import print_function

import os
import re
import signal
import subprocess
import sys
from datetime import datetime, timezone

# ── RFC 5424 inline formatter (Python 3.6-compatible) ─────────────────────────

_FACILITY_LOCAL0 = 16
_SD_ID = "decnet@55555"
_NILVALUE = "-"

SEVERITY_INFO    = 6
SEVERITY_WARNING = 4
SEVERITY_ERROR   = 3


def _sd_escape(value):
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _syslog_line(event_type, severity=SEVERITY_INFO, **fields):
    pri     = "<{}>".format(_FACILITY_LOCAL0 * 8 + severity)
    ts      = datetime.now(timezone.utc).isoformat()
    host    = NODE_NAME[:255]
    appname = "conpot"
    msgid   = event_type[:32]

    if fields:
        params = " ".join('{}="{}"'.format(k, _sd_escape(str(v))) for k, v in fields.items())
        sd = "[{} {}]".format(_SD_ID, params)
    else:
        sd = _NILVALUE

    return "{pri}1 {ts} {host} {appname} {nil} {msgid} {sd}".format(
        pri=pri, ts=ts, host=host, appname=appname,
        nil=_NILVALUE, msgid=msgid, sd=sd,
    )


def _log(event_type, severity=SEVERITY_INFO, **fields):
    print(_syslog_line(event_type, severity, **fields), flush=True)


# ── Config ────────────────────────────────────────────────────────────────────

NODE_NAME = os.environ.get("NODE_NAME", "conpot-node")
TEMPLATE  = os.environ.get("CONPOT_TEMPLATE", "default")

_CONPOT_CMD = [
    "/home/conpot/.local/bin/conpot",
    "--template", TEMPLATE,
    "--logfile", "/var/log/conpot/conpot.log",
    "-f",
    "--temp_dir", "/tmp",
]

# Grab the first routable IPv4 address from a log line
_IP_RE = re.compile(r"\b((?!127\.)(?!0\.)(?!255\.)\d{1,3}(?:\.\d{1,3}){3})\b")

_REQUEST_RE = re.compile(
    r"request|recv|received|connect|session|query|command|"
    r"modbus|snmp|http|s7comm|bacnet|enip",
    re.IGNORECASE,
)
_ERROR_RE   = re.compile(r"error|exception|traceback|critical|fail", re.IGNORECASE)
_WARN_RE    = re.compile(r"warning|warn", re.IGNORECASE)
_STARTUP_RE = re.compile(
    r"starting|started|listening|server|initializ|template|conpot",
    re.IGNORECASE,
)


# ── Classifier ────────────────────────────────────────────────────────────────

def _classify(raw):
    """Return (event_type, severity, fields) for one conpot log line."""
    fields = {}

    m = _IP_RE.search(raw)
    if m:
        fields["src"] = m.group(1)

    fields["msg"] = raw[:300]

    if _ERROR_RE.search(raw):
        return "error", SEVERITY_ERROR, fields
    if _WARN_RE.search(raw):
        return "warning", SEVERITY_WARNING, fields
    if _REQUEST_RE.search(raw):
        return "request", SEVERITY_INFO, fields
    if _STARTUP_RE.search(raw):
        return "startup", SEVERITY_INFO, fields
    return "log", SEVERITY_INFO, fields


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    _log("startup", msg="Conpot ICS honeypot starting (template={})".format(TEMPLATE))

    proc = subprocess.Popen(
        _CONPOT_CMD,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        universal_newlines=True,
    )

    def _forward(sig, _frame):
        proc.send_signal(sig)

    signal.signal(signal.SIGTERM, _forward)
    signal.signal(signal.SIGINT, _forward)

    try:
        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            if not line:
                continue
            event_type, severity, fields = _classify(line)
            _log(event_type, severity, **fields)
    finally:
        proc.wait()
        _log("shutdown", msg="Conpot ICS honeypot stopped")
        sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
