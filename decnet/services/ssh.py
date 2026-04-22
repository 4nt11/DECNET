import os
from pathlib import Path

from decnet.services.base import BaseService

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "ssh"
ARTIFACTS_ROOT = os.environ.get("DECNET_ARTIFACTS_ROOT", "/var/lib/decnet/artifacts")


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
            # NODE_NAME is the authoritative decky identifier for log
            # attribution — matches the host path used for the artifacts
            # bind mount below. The container hostname (optionally overridden
            # via SSH_HOSTNAME) is cosmetic and may differ to keep the
            # decoy looking heterogeneous.
            "NODE_NAME": decky_name,
        }
        if "hostname" in cfg:
            env["SSH_HOSTNAME"] = cfg["hostname"]

        # File-catcher quarantine: bind-mount a per-decky host dir so attacker
        # drops (scp/sftp/wget) are mirrored out-of-band for forensic analysis.
        # The in-container path masquerades as systemd-coredump so `mount`/`df`
        # from inside the container looks benign.
        quarantine_host = f"{ARTIFACTS_ROOT}/{decky_name}/ssh"
        return {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-ssh",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": env,
            "volumes": [f"{quarantine_host}:/var/lib/systemd/coredump:rw"],
        }

    def dockerfile_context(self) -> Path:
        return TEMPLATES_DIR
