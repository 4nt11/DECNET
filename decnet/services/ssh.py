import os
from pathlib import Path

from decnet.services.base import BaseService, ServiceConfigField

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
        password         Root password (default: "admin")
        user             Non-root user name (default: "ubuntu") for
                         realistic "ssh user@host" lures + privesc capture
        user_password    Non-root user's password (default: "admin")
        hostname         Override container hostname
    """

    name = "ssh"
    ports = [22]
    default_image = "build"

    config_schema = [
        ServiceConfigField(
            key="password",
            label="Root password",
            type="password",
            default="admin",
            secret=True,
            help="Plaintext root password for the in-container sshd.",
        ),
        ServiceConfigField(
            key="user",
            label="Non-root user",
            type="string",
            default="ubuntu",
            help=(
                "Username for the second account on the decoy. Real Linux "
                "boxes (especially Ubuntu cloud images) ship a non-root "
                "admin user — having one makes the decoy more lifelike, "
                "captures attackers who try `ssh user@host` for network "
                "enumeration, and surfaces sudo/privesc behaviour the root-"
                "only path misses."
            ),
        ),
        ServiceConfigField(
            key="user_password",
            label="Non-root user password",
            type="password",
            default="admin",
            secret=True,
            help=(
                "Password for the non-root user. Captured at PAM auth time "
                "via the same auth-helper that handles root logins. The "
                "user is in the `sudo` group; subsequent privesc attempts "
                "fan out through the existing sudo-log capture."
            ),
        ),
        ServiceConfigField(
            key="hostname",
            label="Container hostname",
            type="string",
            help=(
                "Cosmetic override for the SSH banner/PS1 — keeps the decoy "
                "looking heterogeneous. Decky identity (NODE_NAME) is unaffected."
            ),
            placeholder="e.g. mail-01.corp.local",
        ),
    ]

    def compose_fragment(
        self,
        decky_name: str,
        log_target: str | None = None,
        service_cfg: dict | None = None,
    ) -> dict:
        cfg = service_cfg or {}
        env: dict = {
            "SSH_ROOT_PASSWORD": cfg.get("password", "admin"),
            # Non-root user account — created at runtime by the entrypoint
            # iff SSH_USER is non-empty. Defaults to "ubuntu"/"admin" so
            # `ssh ubuntu@<decky>` works out of the box (the conventional
            # cloud-init account on Ubuntu cloud images, very low-friction
            # for attackers running ssh enumeration scripts).
            "SSH_USER": cfg.get("user", "ubuntu"),
            "SSH_USER_PASSWORD": cfg.get("user_password", "admin"),
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
