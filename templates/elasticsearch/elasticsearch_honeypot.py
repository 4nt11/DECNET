#!/usr/bin/env python3
"""
Elasticsearch honeypot — presents a convincing ES 7.x HTTP API on port 9200.
Logs all requests (especially recon probes like /_cat/, /_cluster/, /_nodes/)
as JSON. Designed to attract automated scanners and credential stuffers.
"""

import json
import os
import socket
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

HONEYPOT_NAME = os.environ.get("HONEYPOT_NAME", "esserver")
LOG_TARGET = os.environ.get("LOG_TARGET", "")

_CLUSTER_UUID = "xC3Pr9abTq2mNkOeLvXwYA"
_NODE_UUID = "dJH7Lm2sRqWvPn0kFiEtBo"

_ROOT_RESPONSE = {
    "name": HONEYPOT_NAME,
    "cluster_name": "elasticsearch",
    "cluster_uuid": _CLUSTER_UUID,
    "version": {
        "number": "7.17.9",
        "build_flavor": "default",
        "build_type": "docker",
        "build_hash": "ef48222227ee6b9e70e502f0f0daa52435ee634d",
        "build_date": "2023-01-31T05:34:43.305517834Z",
        "build_snapshot": False,
        "lucene_version": "8.11.1",
        "minimum_wire_compatibility_version": "6.8.0",
        "minimum_index_compatibility_version": "6.0.0-beta1",
    },
    "tagline": "You Know, for Search",
}


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
        "service": "elasticsearch",
        "host": HONEYPOT_NAME,
        "event": event_type,
        **kwargs,
    }
    print(json.dumps(event), flush=True)
    _forward(event)


class ESHandler(BaseHTTPRequestHandler):
    server_version = "elasticsearch"
    sys_version = ""

    def _send_json(self, code: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-elastic-product", "Elasticsearch")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self) -> str:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length).decode(errors="replace") if length else ""

    def do_GET(self):
        src = self.client_address[0]
        path = self.path.split("?")[0]

        if path in ("/", ""):
            _log("root_probe", src=src, method="GET", path=self.path)
            self._send_json(200, _ROOT_RESPONSE)
        elif path.startswith("/_cat/"):
            _log("cat_api", src=src, method="GET", path=self.path)
            self._send_json(200, [])
        elif path.startswith("/_cluster/"):
            _log("cluster_recon", src=src, method="GET", path=self.path)
            self._send_json(200, {"cluster_name": "elasticsearch", "status": "green",
                                   "number_of_nodes": 3, "number_of_data_nodes": 3})
        elif path.startswith("/_nodes"):
            _log("nodes_recon", src=src, method="GET", path=self.path)
            self._send_json(200, {"_nodes": {"total": 3, "successful": 3, "failed": 0}, "nodes": {}})
        elif path.startswith("/_security/") or path.startswith("/_xpack/"):
            _log("security_probe", src=src, method="GET", path=self.path)
            self._send_json(200, {"enabled": True, "available": True})
        else:
            _log("request", src=src, method="GET", path=self.path)
            self._send_json(404, {"error": {"root_cause": [{"type": "index_not_found_exception",
                                                             "reason": "no such index"}]}})

    def do_POST(self):
        src = self.client_address[0]
        body = self._read_body()
        path = self.path.split("?")[0]
        _log("post_request", src=src, method="POST", path=self.path,
             body_preview=body[:300], user_agent=self.headers.get("User-Agent", ""))
        if "_search" in path or "_bulk" in path:
            self._send_json(200, {"took": 1, "timed_out": False, "hits": {"total": {"value": 0}, "hits": []}})
        else:
            self._send_json(200, {"result": "created", "_id": "1", "_index": "honeypot"})

    def do_PUT(self):
        src = self.client_address[0]
        body = self._read_body()
        _log("put_request", src=src, method="PUT", path=self.path, body_preview=body[:300])
        self._send_json(200, {"acknowledged": True})

    def do_DELETE(self):
        src = self.client_address[0]
        _log("delete_request", src=src, method="DELETE", path=self.path)
        self._send_json(200, {"acknowledged": True})

    def do_HEAD(self):
        src = self.client_address[0]
        _log("head_request", src=src, method="HEAD", path=self.path)
        self._send_json(200, {})

    def log_message(self, fmt, *args):
        pass  # suppress default HTTP server logging


if __name__ == "__main__":
    _log("startup", msg=f"Elasticsearch honeypot starting as {HONEYPOT_NAME}")
    server = HTTPServer(("0.0.0.0", 9200), ESHandler)
    server.serve_forever()
