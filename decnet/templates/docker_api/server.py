#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Docker APIserver.
Serves a fake Docker REST API on port 2375. Responds to common recon
endpoints (/version, /info, /containers/json, /images/json) with plausible
but fake data. Logs all requests as JSON.
"""

import json
import os

from flask import Flask, request
from syslog_bridge import (
    classify_authorization,
    forward_syslog,
    syslog_line,
    write_syslog_file,
)

NODE_NAME = os.environ.get("NODE_NAME", "docker-host")
SERVICE_NAME   = "docker_api"
LOG_TARGET = os.environ.get("LOG_TARGET", "")

app = Flask(__name__)

_VERSION = {
    "Version": "24.0.5",
    "ApiVersion": "1.43",
    "MinAPIVersion": "1.12",
    "GitCommit": "ced0996",
    "GoVersion": "go1.20.6",
    "Os": "linux",
    "Arch": "amd64",
    "KernelVersion": "5.15.0-76-generic",
}

_INFO = {
    "ID": "FAKE:FAKE:FAKE:FAKE",
    "Containers": 3,
    "ContainersRunning": 3,
    "Images": 7,
    "Driver": "overlay2",
    "MemoryLimit": True,
    "SwapLimit": True,
    "KernelMemory": False,
    "Name": NODE_NAME,
    "DockerRootDir": "/var/lib/docker",
    "HttpProxy": "",
    "HttpsProxy": "",
    "NoProxy": "",
    "ServerVersion": "24.0.5",
}

_CONTAINERS = [
    {
        "Id": "a1b2c3d4e5f6",
        "Names": ["/webapp"],
        "Image": "nginx:latest",
        "State": "running",
        "Status": "Up 3 days",
        "Ports": [{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}],  # nosec B104
    }
]




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


@app.before_request
def log_request():
    cred = classify_authorization(request.headers.get("Authorization"))
    _log(
        "request",
        method=request.method,
        path=request.path,
        remote_addr=request.remote_addr,
        headers=json.dumps(dict(request.headers)),
        body=request.get_data(as_text=True)[:512],
        **(cred or {}),
    )


@app.route("/version")
@app.route("/<ver>/version")
def version(ver=None):
    return app.response_class(json.dumps(_VERSION), mimetype="application/json")


@app.route("/info")
@app.route("/<ver>/info")
def info(ver=None):
    return app.response_class(json.dumps(_INFO), mimetype="application/json")


@app.route("/containers/json")
@app.route("/<ver>/containers/json")
def containers(ver=None):
    return app.response_class(json.dumps(_CONTAINERS), mimetype="application/json")


@app.route("/images/json")
@app.route("/<ver>/images/json")
def images(ver=None):
    return app.response_class(json.dumps([]), mimetype="application/json")


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def catch_all(path):
    return app.response_class(
        json.dumps({"message": "page not found", "response": 404}),
        status=404,
        mimetype="application/json",
    )


if __name__ == "__main__":
    _log("startup", msg=f"Docker API server starting as {NODE_NAME}")
    app.run(host="0.0.0.0", port=2375, debug=False)  # nosec B104
