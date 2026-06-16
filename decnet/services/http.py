# SPDX-License-Identifier: AGPL-3.0-or-later
import json
from pathlib import Path
from decnet.services.base import BaseService, ServiceConfigField

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "http"


class HTTPService(BaseService):
    name = "http"
    ports = [80, 443]
    default_image = "build"

    config_schema = [
        ServiceConfigField(
            key="server_header",
            label="Server header",
            type="string",
            placeholder="Apache/2.4.41 (Ubuntu)",
            help="Value sent in the HTTP Server: response header.",
        ),
        ServiceConfigField(
            key="response_code",
            label="Default response code",
            type="int",
            default=200,
        ),
        ServiceConfigField(
            key="fake_app",
            label="Fake application",
            type="enum",
            enum=["none", "wordpress", "phpmyadmin", "tomcat", "jenkins"],
            default="none",
            help="Pre-baked application skin to render on the index page.",
        ),
        ServiceConfigField(
            key="extra_headers",
            label="Extra headers (JSON or raw)",
            type="textarea",
            placeholder='{"X-Powered-By": "PHP/7.4.3"}',
        ),
        ServiceConfigField(
            key="custom_body",
            label="Custom response body",
            type="textarea",
        ),
        ServiceConfigField(
            key="http_versions",
            label="Supported HTTP versions",
            type="multi_enum",
            enum=["http/1.1", "http/2"],
            default=["http/1.1"],
            help="Protocol versions Caddy advertises. HTTP/3 requires TLS — use the https service.",
        ),
    ]

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        cfg = service_cfg or {}
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-http",
            "restart": "unless-stopped",
            "environment": {
                "NODE_NAME": decky_name,
            },
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target

        # Optional persona overrides — only injected when explicitly set
        if "server_header" in cfg:
            fragment["environment"]["SERVER_HEADER"] = cfg["server_header"]
        if "response_code" in cfg:
            fragment["environment"]["RESPONSE_CODE"] = str(cfg["response_code"])
        if "fake_app" in cfg:
            fragment["environment"]["FAKE_APP"] = cfg["fake_app"]
        if "extra_headers" in cfg:
            val = cfg["extra_headers"]
            fragment["environment"]["EXTRA_HEADERS"] = (
                json.dumps(val) if isinstance(val, dict) else val
            )
        if "custom_body" in cfg:
            fragment["environment"]["CUSTOM_BODY"] = cfg["custom_body"]
        if "http_versions" in cfg:
            fragment["environment"]["HTTP_VERSIONS"] = json.dumps(cfg["http_versions"])
        if "files" in cfg:
            files_path = str(Path(cfg["files"]).resolve())
            fragment["environment"]["FILES_DIR"] = "/opt/html_files"
            fragment.setdefault("volumes", []).append(f"{files_path}:/opt/html_files:ro")

        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
