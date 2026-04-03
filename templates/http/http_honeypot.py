#!/usr/bin/env python3
"""
HTTP honeypot using Flask.
Accepts all requests, logs every detail (method, path, headers, body),
and responds with convincing but empty pages. Forwards events as JSON
to LOG_TARGET if set.
"""

import json
import os
import socket
from datetime import datetime, timezone

from flask import Flask, request

HONEYPOT_NAME = os.environ.get("HONEYPOT_NAME", "webserver")
LOG_TARGET = os.environ.get("LOG_TARGET", "")

app = Flask(__name__)


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
        "service": "http",
        "host": HONEYPOT_NAME,
        "event": event_type,
        **kwargs,
    }
    print(json.dumps(event), flush=True)
    _forward(event)


@app.before_request
def log_request():
    _log(
        "request",
        method=request.method,
        path=request.path,
        remote_addr=request.remote_addr,
        headers=dict(request.headers),
        body=request.get_data(as_text=True)[:512],
    )


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def catch_all(path):
    return (
        "<html><body><h1>403 Forbidden</h1></body></html>",
        403,
        {"Server": "Apache/2.4.54 (Debian)", "Content-Type": "text/html"},
    )


if __name__ == "__main__":
    _log("startup", msg=f"HTTP honeypot starting as {HONEYPOT_NAME}")
    app.run(host="0.0.0.0", port=80, debug=False)
