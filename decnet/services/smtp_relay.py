import os
from pathlib import Path

from decnet.services.base import BaseService, ServiceConfigField

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
        ServiceConfigField(
            key="upstream_host",
            label="Upstream relay host",
            type="string",
            placeholder="smtp.sendgrid.net",
            help="Real SMTP relay used to forward probe emails. Leave blank to disable forwarding.",
        ),
        ServiceConfigField(
            key="upstream_port",
            label="Upstream relay port",
            type="int",
            default=25,
            help="Port on the upstream relay (25 or 587).",
        ),
        ServiceConfigField(
            key="upstream_user",
            label="Upstream relay username",
            type="string",
            help="AUTH username for the upstream relay (optional).",
        ),
        ServiceConfigField(
            key="upstream_pass",
            label="Upstream relay password",
            type="string",
            help="AUTH password for the upstream relay (optional).",
        ),
        ServiceConfigField(
            key="upstream_sender",
            label="Upstream envelope sender",
            type="string",
            placeholder="probe@yourdomain.com",
            help="Envelope MAIL FROM used when talking to the upstream relay. Set this to an address your server is authorised to send from so SPF passes at the recipient. The attacker's From: header inside the message is untouched.",
        ),
        ServiceConfigField(
            key="probe_limit",
            label="Probe forward limit",
            type="int",
            default=1,
            help="Number of emails per source IP to actually deliver upstream. All subsequent emails are silently quarantined.",
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
            "build": {"context": str(_TEMPLATES_DIR)},
            "container_name": f"{decky_name}-smtp_relay",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": {
                "NODE_NAME": decky_name,
                "SMTP_SERVICE_NAME": "smtp_relay",
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
