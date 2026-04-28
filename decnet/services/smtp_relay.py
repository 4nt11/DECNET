import os
from pathlib import Path

from decnet.services.base import BaseService

# Reuses the same template as the smtp service — only difference is
# SMTP_OPEN_RELAY=1 in the environment, which enables the open relay persona.
_TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "smtp"
ARTIFACTS_ROOT = os.environ.get("DECNET_ARTIFACTS_ROOT", "/var/lib/decnet/artifacts")
# See decnet/services/smtp.py — benign-looking in-container quarantine path.
_IN_CONTAINER_QUARANTINE = "/var/spool/mqueue"


class SMTPRelayService(BaseService):
    """SMTP open relay bait — accepts any RCPT TO and delivers messages."""

    name = "smtp_relay"
    ports = [25, 587]
    default_image = "build"

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        cfg = service_cfg or {}
        quarantine_host = f"{ARTIFACTS_ROOT}/{decky_name}/smtp"
        fragment: dict = {
            "build": {"context": str(_TEMPLATES_DIR)},
            "container_name": f"{decky_name}-smtp_relay",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": {
                "NODE_NAME": decky_name,
                "SMTP_OPEN_RELAY": "1",
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
        return _TEMPLATES_DIR
