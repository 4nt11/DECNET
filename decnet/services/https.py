import json
from pathlib import Path
from decnet.services.base import BaseService, ServiceConfigField

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "https"


class HTTPSService(BaseService):
    name = "https"
    ports = [443]
    default_image = "build"

    config_schema = [
        ServiceConfigField(
            key="server_header",
            label="Server header",
            type="string",
            placeholder="nginx/1.18.0",
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
        ),
        ServiceConfigField(
            key="extra_headers",
            label="Extra headers (JSON or raw)",
            type="textarea",
        ),
        ServiceConfigField(
            key="custom_body",
            label="Custom response body",
            type="textarea",
        ),
        ServiceConfigField(
            key="tls_cn",
            label="TLS certificate CN",
            type="string",
            placeholder="mail.corp.local",
            help="Common Name baked into the self-signed cert if no cert/key provided.",
        ),
        ServiceConfigField(
            key="tls_cert",
            label="TLS certificate (PEM)",
            type="textarea",
            secret=True,
        ),
        ServiceConfigField(
            key="tls_key",
            label="TLS private key (PEM)",
            type="textarea",
            secret=True,
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
            "container_name": f"{decky_name}-https",
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
        if "files" in cfg:
            files_path = str(Path(cfg["files"]).resolve())
            fragment["environment"]["FILES_DIR"] = "/opt/html_files"
            fragment.setdefault("volumes", []).append(f"{files_path}:/opt/html_files:ro")
        if "tls_cert" in cfg:
            fragment["environment"]["TLS_CERT"] = cfg["tls_cert"]
        if "tls_key" in cfg:
            fragment["environment"]["TLS_KEY"] = cfg["tls_key"]
        if "tls_cn" in cfg:
            fragment["environment"]["TLS_CN"] = cfg["tls_cn"]

        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
