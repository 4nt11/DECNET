from pathlib import Path

from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates" / "ssh"


class SSHService(BaseService):
    """
    Interactive OpenSSH server for general-purpose deckies.

    Replaced Cowrie emulation with a real sshd so fingerprinting tools and
    experienced attackers cannot trivially identify the honeypot.  Auth events,
    sudo activity, and interactive commands are all forwarded to stdout as
    RFC 5424 via the rsyslog bridge baked into the image.

    service_cfg keys:
        password      Root password (default: "admin")
        hostname      Override container hostname
    """

    name = "ssh"
    ports = [22]
    default_image = "build"

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        cfg = service_cfg or {}
        env: dict = {
            "SSH_ROOT_PASSWORD": cfg.get("password", "admin"),
        }
        if "hostname" in cfg:
            env["SSH_HOSTNAME"] = cfg["hostname"]

        return {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-ssh",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": env,
        }

    def dockerfile_context(self) -> Path:
        return TEMPLATES_DIR
