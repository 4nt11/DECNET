import os
from pathlib import Path

from decnet.services.base import BaseService, ServiceConfigField

TEMPLATES_DIR = Path(__file__).parent.parent / "templates" / "telnet"
ARTIFACTS_ROOT = os.environ.get("DECNET_ARTIFACTS_ROOT", "/var/lib/decnet/artifacts")


class TelnetService(BaseService):
    """
    Real telnetd using busybox telnetd + rsyslog logging pipeline.

    Replaced Cowrie emulation (which also started an SSH daemon on port 22)
    with a real busybox telnetd so only port 23 is exposed and auth events
    are logged as RFC 5424 via the same rsyslog bridge used by the SSH service.

    service_cfg keys:
        password         Root password (default: "admin")
        user             Non-root user name (default: "ubuntu") for
                         realistic "telnet user@host" lures + privesc capture
        user_password    Non-root user's password (default: "admin")
        hostname         Override container hostname
    """

    name = "telnet"
    ports = [23]
    default_image = "build"

    config_schema = [
        ServiceConfigField(
            key="password",
            label="Root password",
            type="password",
            default="admin",
            secret=True,
            help="Plaintext root password for the in-container telnetd.",
        ),
        ServiceConfigField(
            key="user",
            label="Non-root user",
            type="string",
            default="ubuntu",
            help=(
                "Username for the second account on the decoy. The telnet "
                "image is busybox + real /bin/login (PAM-aware), so a "
                "non-root user widens the attack surface — captures "
                "enumeration scripts that only try common usernames "
                "(`telnet ubuntu@host`) and post-login `su -` privesc "
                "attempts via the existing PAM auth-helper."
            ),
        ),
        ServiceConfigField(
            key="user_password",
            label="Non-root user password",
            type="password",
            default="admin",
            secret=True,
            help=(
                "Password for the non-root user. Captured at PAM auth "
                "time via the same auth-helper that handles root logins. "
                "Telnet has no sudo (busybox+login image); privesc rides "
                "`su -` which itself flows through PAM."
            ),
        ),
        ServiceConfigField(
            key="hostname",
            label="Container hostname",
            type="string",
            placeholder="e.g. mail-01.corp.local",
            help=(
                "Cosmetic override for the telnet banner — keeps decoys "
                "looking heterogeneous. Decky identity (NODE_NAME) is unaffected."
            ),
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
            "TELNET_ROOT_PASSWORD": cfg.get("password", "admin"),
            # Non-root user account — created at runtime by the
            # entrypoint iff TELNET_USER is non-empty. Defaults to
            # "ubuntu"/"admin" to mirror the SSH service shape and
            # match the Ubuntu-flavoured motd already baked into the
            # telnet image.
            "TELNET_USER": cfg.get("user", "ubuntu"),
            "TELNET_USER_PASSWORD": cfg.get("user_password", "admin"),
            # NODE_NAME is the authoritative decky identifier for log
            # attribution — matches the host path used for the artifacts
            # bind mount below.
            "NODE_NAME": decky_name,
        }
        if "hostname" in cfg:
            env["TELNET_HOSTNAME"] = cfg["hostname"]

        # Quarantine mount symmetric to the SSH service — sessrec appends
        # pty transcripts to /var/lib/systemd/coredump/transcripts/ inside
        # the container, which the host sees under artifacts/<decky>/telnet/.
        quarantine_host = f"{ARTIFACTS_ROOT}/{decky_name}/telnet"
        return {
            "build": {"context": str(TEMPLATES_DIR)},
            "container_name": f"{decky_name}-telnet",
            "restart": "unless-stopped",
            "cap_add": ["NET_BIND_SERVICE"],
            "environment": env,
            "volumes": [f"{quarantine_host}:/var/lib/systemd/coredump:rw"],
        }

    def dockerfile_context(self) -> Path:
        return TEMPLATES_DIR
