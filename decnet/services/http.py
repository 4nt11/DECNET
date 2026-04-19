import json
from pathlib import Path
from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "http"


class HTTPService(BaseService):
    name = "http"
    ports = [80, 443]
    default_image = "build"

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
        if "files" in cfg:
            files_path = str(Path(cfg["files"]).resolve())
            fragment["environment"]["FILES_DIR"] = "/opt/html_files"
            fragment.setdefault("volumes", []).append(f"{files_path}:/opt/html_files:ro")

        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
