"""Action picker for the orchestrator.

MVP policy: flat random — pick one (src, dst) pair where both deckies
expose SSH, then choose one of {ssh-traffic, file-touch}. No diurnal
shaping, no role-aware pairing — those land in v1.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

# A small set of plausible filenames the orchestrator drops or refreshes.
# Scope on purpose: the file driver is "prove the docker-exec write path
# works", not "generate believable user activity". Realism is v2.
# Paths target the filesystem *inside* a decoy container, not the host.
# Bandit B108 is a host-side concern; suppressed at the data definition.
_FILE_TEMPLATES: tuple[tuple[str, str], ...] = (  # nosec B108
    ("/tmp/.cache-{ts}.tmp", "session={ts}\n"),  # nosec B108
    ("/var/log/cron-{ts}.log", "{ts} CRON[{n}]: ({user}) CMD (run-parts /etc/cron.daily)\n"),
    ("/home/{user}/notes-{ts}.txt", "todo: rotate keys; check on backup task\n"),
)

_USERS = ("admin", "ubuntu", "service")


@dataclass(frozen=True)
class TrafficAction:
    src_uuid: str
    src_name: str
    dst_uuid: str
    dst_name: str
    dst_ip: str
    protocol: str = "ssh"
    description: str = "tcp_connect:22"


@dataclass(frozen=True)
class FileAction:
    dst_uuid: str
    dst_name: str
    path: str
    content: str
    description: str = "file:create"


Action = TrafficAction | FileAction


def _has_ssh(decky: dict[str, Any]) -> bool:
    services = decky.get("services") or []
    if isinstance(services, str):
        return False  # not deserialised — treat as "we don't know"
    return "ssh" in services


def pick(
    deckies: Sequence[dict[str, Any]],
    *,
    rand: Optional[secrets.SystemRandom] = None,
) -> Optional[Action]:
    """Pick one action against the given decky set.

    Returns ``None`` when no action is possible (fewer than two SSH-capable
    deckies for traffic, or no deckies at all for file ops). The worker
    treats ``None`` as "skip this tick".
    """
    rng = rand or secrets.SystemRandom()
    ssh_deckies = [d for d in deckies if _has_ssh(d) and d.get("ip")]
    if not ssh_deckies:
        return None

    kind = "traffic" if (len(ssh_deckies) >= 2 and rng.random() < 0.5) else "file"

    if kind == "traffic":
        src, dst = rng.sample(ssh_deckies, 2)
        return TrafficAction(
            src_uuid=src["uuid"],
            src_name=src["name"],
            dst_uuid=dst["uuid"],
            dst_name=dst["name"],
            dst_ip=dst["ip"],
        )

    dst = rng.choice(ssh_deckies)
    template, content_template = rng.choice(_FILE_TEMPLATES)
    ts = int(datetime.now(timezone.utc).timestamp())
    user = rng.choice(_USERS)
    path = template.format(ts=ts, user=user)
    content = content_template.format(ts=ts, user=user, n=rng.randint(1000, 99999))
    return FileAction(
        dst_uuid=dst["uuid"],
        dst_name=dst["name"],
        path=path,
        content=content,
    )
