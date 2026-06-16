#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Elasticsearch server — presents a convincing ES 7.x HTTP API on port 9200.
Logs all requests (especially recon probes like /_cat/, /_cluster/, /_nodes/)
as JSON. Designed to attract automated scanners and credential stuffers.
"""

import base64
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

import instance_seed as _seed
from syslog_bridge import (
    classify_authorization,
    forward_syslog,
    syslog_line,
    write_syslog_file,
)

NODE_NAME = os.environ.get("NODE_NAME", "esserver")
SERVICE_NAME   = "elasticsearch"
LOG_TARGET = os.environ.get("LOG_TARGET", "")

# Real ES cluster/node UUIDs are 22-char base64 (16 random bytes,
# URL-safe, unpadded). Generate deterministically per instance.
def _es_uuid(namespace: str) -> str:
    raw = _seed.random_bytes(16, namespace)
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


_CLUSTER_UUID = _es_uuid("es-cluster")
_NODE_UUID = _es_uuid("es-node")
_CLUSTER_NAME = os.environ.get("ES_CLUSTER_NAME") or _seed.pick([
    "elasticsearch", "logs", "search-prod", "metrics", "siem-cluster",
    "docker-cluster",
])

# Realistic (version, build_hash, build_date, lucene_version) tuples taken
# from real ES release metadata. Build-hashes change per release; pairing
# them correctly is what makes the version check survive a real client
# reading /_nodes and comparing against its known-versions table.
_ES_RELEASES = [
    ("7.17.9",  "ef48222227ee6b9e70e502f0f0daa52435ee634d", "2023-01-31T05:34:43.305517834Z", "8.11.1"),
    ("7.17.14", "774e3bfa4d52e2834e4d9fdbb4b462fa1ba1cc5a", "2023-10-05T12:16:58.531639647Z", "8.11.1"),
    ("7.17.18", "8682172c2130b9a411b1bd1ff37c2f4f15f04c7b", "2024-02-02T16:43:31.000Z",        "8.11.1"),
    ("8.10.4",  "b4a62ac808e886ff032700c391f45f1408b2538c", "2023-10-11T22:04:35.506990650Z", "9.7.0"),
    ("8.11.4",  "49b9bd5ec73c11d7b49dbd6ffc70b9ea2cdb67d0", "2023-12-19T16:57:03.000Z",        "9.8.0"),
    ("8.12.2",  "48a287ab9497e852de30327444b0809e55d46466", "2024-02-15T15:25:20.000Z",        "9.9.2"),
    ("8.13.4",  "da95df118650b55a500dcc181889ac35c6d8da7c", "2024-05-07T15:39:32.000Z",        "9.10.0"),
]
_ES_VERSION, _ES_BUILD_HASH, _ES_BUILD_DATE, _ES_LUCENE = _seed.pick(_ES_RELEASES)

# Wire-compat rules in ES are hard-coded per major: pick the right ones.
if _ES_VERSION.startswith("8."):
    _MIN_WIRE = "7.17.0"
    _MIN_INDEX = "7.0.0"
else:
    _MIN_WIRE = "6.8.0"
    _MIN_INDEX = "6.0.0-beta1"

# Per-instance cluster size — shapes /_cat/nodes + /_cluster/health output.
_CLUSTER_NODES = _seed.rng.choice([1, 1, 3, 3, 3, 5, 5, 7])


_ROOT_RESPONSE = {
    "name": NODE_NAME,
    "cluster_name": _CLUSTER_NAME,
    "cluster_uuid": _CLUSTER_UUID,
    "version": {
        "number": _ES_VERSION,
        "build_flavor": "default",
        "build_type": "docker",
        "build_hash": _ES_BUILD_HASH,
        "build_date": _ES_BUILD_DATE,
        "build_snapshot": False,
        "lucene_version": _ES_LUCENE,
        "minimum_wire_compatibility_version": _MIN_WIRE,
        "minimum_index_compatibility_version": _MIN_INDEX,
    },
    "tagline": "You Know, for Search",
}




def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


class ESHandler(BaseHTTPRequestHandler):
    server_version = "elasticsearch"
    sys_version = ""

    def _send_json(self, code: int, data: dict | list) -> None:
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

    def _cred_fields(self) -> dict:
        """Universal cred shape from this request's Authorization header,
        or empty dict when absent / unrecognized."""
        return classify_authorization(self.headers.get("Authorization")) or {}

    def do_GET(self):
        src = self.client_address[0]
        path = self.path.split("?")[0]

        if path in ("/", ""):
            _log("root_probe", src=src, method="GET", path=self.path, **self._cred_fields())
            self._send_json(200, _ROOT_RESPONSE)
        elif path.startswith("/_cat/"):
            _log("cat_api", src=src, method="GET", path=self.path, **self._cred_fields())
            self._send_json(200, [])
        elif path.startswith("/_cluster/"):
            _log("cluster_recon", src=src, method="GET", path=self.path, **self._cred_fields())
            self._send_json(200, {
                "cluster_name": _CLUSTER_NAME,
                "cluster_uuid": _CLUSTER_UUID,
                "status": _seed.pick(["green", "green", "green", "yellow"]),
                "timed_out": False,
                "number_of_nodes": _CLUSTER_NODES,
                "number_of_data_nodes": _CLUSTER_NODES,
                "active_primary_shards": _seed.rng.randint(5, 180),
                "active_shards": _seed.rng.randint(10, 360),
                "relocating_shards": 0,
                "initializing_shards": 0,
                "unassigned_shards": 0,
                "active_shards_percent_as_number": 100.0,
            })
        elif path.startswith("/_nodes"):
            _log("nodes_recon", src=src, method="GET", path=self.path, **self._cred_fields())
            self._send_json(200, {
                "_nodes": {"total": _CLUSTER_NODES, "successful": _CLUSTER_NODES, "failed": 0},
                "cluster_name": _CLUSTER_NAME,
                "nodes": {_NODE_UUID: {"name": NODE_NAME, "version": _ES_VERSION,
                                       "build_hash": _ES_BUILD_HASH}},
            })
        elif path.startswith("/_security/") or path.startswith("/_xpack/"):
            _log("security_probe", src=src, method="GET", path=self.path, **self._cred_fields())
            self._send_json(200, {"enabled": True, "available": True})
        else:
            _log("request", src=src, method="GET", path=self.path, **self._cred_fields())
            self._send_json(404, {"error": {"root_cause": [{"type": "index_not_found_exception",
                                                             "reason": "no such index"}]}})

    def do_POST(self):
        src = self.client_address[0]
        body = self._read_body()
        path = self.path.split("?")[0]
        _log("post_request", src=src, method="POST", path=self.path,
             body_preview=body[:300], user_agent=self.headers.get("User-Agent", ""),
             **self._cred_fields())
        if "_search" in path or "_bulk" in path:
            self._send_json(200, {"took": 1, "timed_out": False, "hits": {"total": {"value": 0}, "hits": []}})
        else:
            self._send_json(200, {"result": "created", "_id": "1", "_index": "server"})

    def do_PUT(self):
        src = self.client_address[0]
        body = self._read_body()
        _log("put_request", src=src, method="PUT", path=self.path,
             body_preview=body[:300], **self._cred_fields())
        self._send_json(200, {"acknowledged": True})

    def do_DELETE(self):
        src = self.client_address[0]
        _log("delete_request", src=src, method="DELETE", path=self.path,
             **self._cred_fields())
        self._send_json(200, {"acknowledged": True})

    def do_HEAD(self):
        src = self.client_address[0]
        _log("head_request", src=src, method="HEAD", path=self.path,
             **self._cred_fields())
        self._send_json(200, {})

    def log_message(self, fmt, *args):
        pass  # suppress default HTTP server logging


if __name__ == "__main__":
    _log("startup", msg=f"Elasticsearch server starting as {NODE_NAME}")
    server = HTTPServer(("0.0.0.0", 9200), ESHandler)  # nosec B104
    server.serve_forever()
