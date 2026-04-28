#!/usr/bin/env python3
"""
Kubernetes APIserver.
Serves a fake K8s REST API on port 6443 (HTTPS-ish, plain HTTP) and 8080.
Responds to recon endpoints (/version, /api, /apis, /api/v1/namespaces,
/api/v1/pods) with plausible but fake data. Logs all requests as JSON.
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

NODE_NAME = os.environ.get("NODE_NAME", "k8s-master")
SERVICE_NAME   = "k8s"
LOG_TARGET = os.environ.get("LOG_TARGET", "")

app = Flask(__name__)

_VERSION = {
    "major": "1",
    "minor": "27",
    "gitVersion": "v1.27.4",
    "gitCommit": "fa3d7990104d7c1f16943a67f11b154b71f6a132",
    "gitTreeState": "clean",
    "buildDate": "2023-07-19T12:14:46Z",
    "goVersion": "go1.20.6",
    "compiler": "gc",
    "platform": "linux/amd64",
}

_API_VERSIONS = {
    "kind": "APIVersions",
    "versions": ["v1"],
    "serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0", "serverAddress": f"{NODE_NAME}:6443"}],
}

_NAMESPACES = {
    "kind": "NamespaceList",
    "apiVersion": "v1",
    "items": [
        {"metadata": {"name": "default"}},
        {"metadata": {"name": "kube-system"}},
        {"metadata": {"name": "production"}},
    ],
}

_PODS = {
    "kind": "PodList",
    "apiVersion": "v1",
    "items": [
        {"metadata": {"name": "webapp-6d5f8b9-xk2p7", "namespace": "production"},
         "status": {"phase": "Running"}},
    ],
}

_SECRETS = {
    "kind": "Status",
    "apiVersion": "v1",
    "status": "Failure",
    "message": "secrets is forbidden: User \"system:anonymous\" cannot list resource \"secrets\"",
    "reason": "Forbidden",
    "code": 403,
}




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


@app.before_request
def log_request():
    auth_header = request.headers.get("Authorization", "")
    cred = classify_authorization(auth_header)
    _log(
        "request",
        method=request.method,
        path=request.path,
        remote_addr=request.remote_addr,
        auth=auth_header,
        body=request.get_data(as_text=True)[:512],
        **(cred or {}),
    )


@app.route("/version")
def version():
    return app.response_class(json.dumps(_VERSION), mimetype="application/json")


@app.route("/api")
def api():
    return app.response_class(json.dumps(_API_VERSIONS), mimetype="application/json")


@app.route("/api/v1/namespaces")
def namespaces():
    return app.response_class(json.dumps(_NAMESPACES), mimetype="application/json")


@app.route("/api/v1/pods")
@app.route("/api/v1/namespaces/<ns>/pods")
def pods(ns="default"):
    return app.response_class(json.dumps(_PODS), mimetype="application/json")


@app.route("/api/v1/secrets")
@app.route("/api/v1/namespaces/<ns>/secrets")
def secrets(ns="default"):
    return app.response_class(json.dumps(_SECRETS), status=403, mimetype="application/json")


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def catch_all(path):
    return app.response_class(
        json.dumps({"kind": "Status", "status": "Failure", "code": 404}),
        status=404,
        mimetype="application/json",
    )


if __name__ == "__main__":
    _log("startup", msg=f"Kubernetes API server starting as {NODE_NAME}")
    app.run(host="0.0.0.0", port=6443, debug=False)  # nosec B104
