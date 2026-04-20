#!/usr/bin/env python3
"""
HTTP service emulator using Flask.
Accepts all requests, logs every detail (method, path, headers, body),
and responds with configurable pages. Forwards events as JSON to LOG_TARGET if set.
"""

import json
import logging
import os
from pathlib import Path

from flask import Flask, request, send_from_directory
from werkzeug.serving import make_server, WSGIRequestHandler
from syslog_bridge import syslog_line, write_syslog_file, forward_syslog

logging.getLogger("werkzeug").setLevel(logging.ERROR)

NODE_NAME     = os.environ.get("NODE_NAME", "webserver")
SERVICE_NAME   = "http"
LOG_TARGET    = os.environ.get("LOG_TARGET", "")
PORT          = int(os.environ.get("PORT", "80"))
SERVER_HEADER = os.environ.get("SERVER_HEADER", "Apache/2.4.54 (Debian)")
RESPONSE_CODE = int(os.environ.get("RESPONSE_CODE", "403"))
FAKE_APP      = os.environ.get("FAKE_APP", "")
EXTRA_HEADERS = json.loads(os.environ.get("EXTRA_HEADERS", "{}"))
CUSTOM_BODY   = os.environ.get("CUSTOM_BODY", "")
FILES_DIR     = os.environ.get("FILES_DIR", "")

_FAKE_APP_BODIES: dict[str, str] = {
    "apache_default": (
        "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
        "<html><head><title>Apache2 Debian Default Page</title></head>\n"
        "<body><h1>Apache2 Debian Default Page</h1>\n"
        "<p>It works!</p></body></html>"
    ),
    "nginx_default": (
        "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head>\n"
        "<body><h1>Welcome to nginx!</h1>\n"
        "<p>If you see this page, the nginx web server is successfully installed.</p>\n"
        "</body></html>"
    ),
    "wordpress": (
        "<!DOCTYPE html><html><head><title>WordPress &rsaquo; Error</title></head>\n"
        "<body id=\"error-page\"><div class=\"wp-die-message\">\n"
        "<h1>Error establishing a database connection</h1></div></body></html>"
    ),
    "phpmyadmin": (
        "<!DOCTYPE html><html><head><title>phpMyAdmin</title></head>\n"
        "<body><form method=\"post\" action=\"index.php\">\n"
        "<input type=\"text\" name=\"pma_username\" />\n"
        "<input type=\"password\" name=\"pma_password\" />\n"
        "<input type=\"submit\" value=\"Go\" /></form></body></html>"
    ),
    "iis_default": (
        "<!DOCTYPE html><html><head><title>IIS Windows Server</title></head>\n"
        "<body><h1>IIS Windows Server</h1>\n"
        "<p>Welcome to Internet Information Services</p></body></html>"
    ),
}

app = Flask(__name__)

@app.after_request
def _fix_server_header(response):
    response.headers["Server"] = SERVER_HEADER
    return response

def _log(event_type: str, severity: int = 6, **kwargs) -> None:
    line = syslog_line(SERVICE_NAME, NODE_NAME, event_type, severity, **kwargs)
    write_syslog_file(line)
    forward_syslog(line, LOG_TARGET)


@app.before_request
def log_request():
    _log(
        "request",
        method=request.method,
        path=request.path,
        remote_addr=request.remote_addr,
        headers=json.dumps(dict(request.headers)),
        body=request.get_data(as_text=True)[:512],
    )


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def catch_all(path):
    # Serve static files directory if configured
    if FILES_DIR and path:
        files_path = Path(FILES_DIR) / path
        if files_path.is_file():
            return send_from_directory(FILES_DIR, path)

    # Select response body: custom > fake_app preset > default 403
    if CUSTOM_BODY:
        body = CUSTOM_BODY
    elif FAKE_APP and FAKE_APP in _FAKE_APP_BODIES:
        body = _FAKE_APP_BODIES[FAKE_APP]
    else:
        body = (
            "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            "<html><head>\n"
            "<title>403 Forbidden</title>\n"
            "</head><body>\n"
            "<h1>Forbidden</h1>\n"
            "<p>You don't have permission to access this resource.</p>\n"
            "<hr>\n"
            f"<address>{SERVER_HEADER} Server at {NODE_NAME} Port 80</address>\n"
            "</body></html>\n"
        )

    headers = {"Content-Type": "text/html", **EXTRA_HEADERS}
    return body, RESPONSE_CODE, headers


class _SilentHandler(WSGIRequestHandler):
    """Suppress Werkzeug's Server header so Flask's after_request is the sole source."""
    def version_string(self) -> str:
        return ""


if __name__ == "__main__":
    _log("startup", msg=f"HTTP server starting as {NODE_NAME}")
    srv = make_server("0.0.0.0", PORT, app, request_handler=_SilentHandler)  # nosec B104
    srv.serve_forever()
