from __future__ import annotations

import typer

from decnet.env import DECNET_API_PORT, DECNET_WEB_HOST, DECNET_WEB_PORT

from . import utils as _utils
from .utils import console, log


def register(app: typer.Typer) -> None:
    @app.command(name="web")
    def serve_web(
        web_port: int = typer.Option(DECNET_WEB_PORT, "--web-port", help="Port to serve the DECNET Web Dashboard"),
        host: str = typer.Option(DECNET_WEB_HOST, "--host", help="Host IP to serve the Web Dashboard"),
        api_port: int = typer.Option(DECNET_API_PORT, "--api-port", help="Port the DECNET API is listening on"),
        daemon: bool = typer.Option(False, "--daemon", "-d", help="Detach to background as a daemon process"),
    ) -> None:
        """Serve the DECNET Web Dashboard frontend.

        Proxies /api/* requests to the API server so the frontend can use
        relative URLs (/api/v1/...) with no CORS configuration required.
        """
        import http.client
        import http.server
        import os
        import socketserver
        from pathlib import Path

        dist_dir = Path(__file__).resolve().parent.parent.parent / "decnet_web" / "dist"

        if not dist_dir.exists():
            console.print(f"[red]Frontend build not found at {dist_dir}. Make sure you run 'npm run build' inside 'decnet_web'.[/]")
            raise typer.Exit(1)

        if daemon:
            log.info("web daemonizing host=%s port=%d api_port=%d", host, web_port, api_port)
            _utils._daemonize()

        _api_port = api_port

        class SPAHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path.startswith("/api/"):
                    self._proxy("GET")
                    return
                path = self.translate_path(self.path)
                if not Path(path).exists() or Path(path).is_dir():
                    self.path = "/index.html"
                return super().do_GET()

            def do_POST(self):
                if self.path.startswith("/api/"):
                    self._proxy("POST")
                    return
                self.send_error(405)

            def do_PUT(self):
                if self.path.startswith("/api/"):
                    self._proxy("PUT")
                    return
                self.send_error(405)

            def do_DELETE(self):
                if self.path.startswith("/api/"):
                    self._proxy("DELETE")
                    return
                self.send_error(405)

            def do_PATCH(self):
                if self.path.startswith("/api/"):
                    self._proxy("PATCH")
                    return
                self.send_error(405)

            def do_OPTIONS(self):
                if self.path.startswith("/api/"):
                    self._proxy("OPTIONS")
                    return
                self.send_error(405)

            def _proxy(self, method: str) -> None:
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else None

                forward = {k: v for k, v in self.headers.items()
                           if k.lower() not in ("host", "connection")}

                try:
                    conn = http.client.HTTPConnection("127.0.0.1", _api_port, timeout=120)
                    conn.request(method, self.path, body=body, headers=forward)
                    resp = conn.getresponse()

                    self.send_response(resp.status)
                    for key, val in resp.getheaders():
                        if key.lower() not in ("connection", "transfer-encoding"):
                            self.send_header(key, val)
                    self.end_headers()

                    content_type = resp.getheader("Content-Type", "")
                    if "text/event-stream" in content_type:
                        conn.sock.settimeout(None)

                    _read = getattr(resp, "read1", resp.read)
                    while True:
                        chunk = _read(4096)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        self.wfile.flush()
                except Exception as exc:
                    log.warning("web proxy error %s %s: %s", method, self.path, exc)
                    self.send_error(502, f"API proxy error: {exc}")
                finally:
                    try:
                        conn.close()
                    except Exception:  # nosec B110 — best-effort conn cleanup
                        pass

            def log_message(self, fmt: str, *args: object) -> None:
                log.debug("web %s", fmt % args)

        os.chdir(dist_dir)

        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.ThreadingTCPServer((host, web_port), SPAHTTPRequestHandler) as httpd:
            console.print(f"[green]Serving DECNET Web Dashboard on http://{host}:{web_port}[/]")
            console.print(f"[dim]Proxying /api/* → http://127.0.0.1:{_api_port}[/]")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                console.print("\n[dim]Shutting down dashboard server.[/]")
