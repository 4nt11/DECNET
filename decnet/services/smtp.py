import os
from pathlib import Path

from decnet.services.base import BaseService, ServiceConfigField

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "smtp"
ARTIFACTS_ROOT = os.environ.get("DECNET_ARTIFACTS_ROOT", "/var/lib/decnet/artifacts")
# In-container path for full-message capture. /var/spool/mqueue is where
# sendmail historically parks unsent messages, so `ls` / `mount` inside the
# container looks benign to an attacker poking around.
_IN_CONTAINER_QUARANTINE = "/var/spool/mqueue"


class SMTPService(BaseService):
    name = "smtp"
    ports = [25, 587]
    default_image = "build"

    config_schema = [
        ServiceConfigField(
            key="banner",
            label="SMTP greeting banner",
            type="string",
            placeholder="mail.corp.local ESMTP Postfix",
            help="First line returned on TCP connect (220 ...).",
        ),
        ServiceConfigField(
            key="mta",
            label="MTA persona",
            type="enum",
            enum=["postfix", "exim", "sendmail"],
            default="postfix",
            help="Shapes EHLO capability list and error wording.",
        ),
    ]

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        cfg = service_cfg or {}
        quarantine_host = f"{ARTIFACTS_ROOT}/{decky_name}/smtp"
        fragment: dict = {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-smtp",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": {
                "NODE_NAME": decky_name,
                "SMTP_QUARANTINE_DIR": _IN_CONTAINER_QUARANTINE,
            },
            "volumes": [f"{quarantine_host}:{_IN_CONTAINER_QUARANTINE}:rw"],
        }
        if log_target:
            fragment["environment"]["LOG_TARGET"] = log_target
        if "banner" in cfg:
            fragment["environment"]["SMTP_BANNER"] = cfg["banner"]
        if "mta" in cfg:
            fragment["environment"]["SMTP_MTA"] = cfg["mta"]
        return fragment

    def dockerfile_context(self) -> Path:
        return TEMPLATES_DIR
