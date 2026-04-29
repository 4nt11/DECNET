from pathlib import Path
from decnet.services.base import BaseService, ServiceConfigField

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "mysql"


class MySQLService(BaseService):
    name = "mysql"
    ports = [3306]
    default_image = "build"

    config_schema = [
        ServiceConfigField(
            key="version",
            label="Advertised MySQL version",
            type="string",
            placeholder="8.0.36",
            help="Sets the version banner the fake MySQL handshake reports.",
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
            "container_name": f"{decky_name}-mysql",
            "restart": "unless-stopped",
            "environment": {"NODE_NAME": decky_name},
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        if "version" in cfg:
            fragment["environment"]["MYSQL_VERSION"] = cfg["version"]
        return fragment

    def dockerfile_context(self) -> Path | None:
        return TEMPLATES_DIR
