"""Persona-aware path resolution for canary artifacts.

Linux-persona deckies use POSIX-shaped paths under ``/home/<user>``.
"Windows" personas (still Linux containers under the hood — see
:mod:`decnet.archetypes`) use Windows-shaped paths under
``/home/<user>/AppData/...`` so an attacker browsing the filesystem
through a planted RDP/SMB session sees the right shape.

The persona lookup is best-effort: callers pass the
:attr:`decnet.archetypes.Archetype.nmap_os` value (``"linux"`` or
``"windows"``); unknown personas fall through to ``"linux"``.
Operators can always override by passing an explicit
``placement_path`` when creating a token.
"""
from __future__ import annotations

DEFAULT_LINUX_USER = "admin"
DEFAULT_WINDOWS_USER = "Administrator"

# Canonical placements for the synthesizer-driven baseline tokens.
# Operators can override per-token via the API, but these are the
# defaults the deploy-time seed uses.
_LINUX_DEFAULTS: dict[str, str] = {
    "git_config": "/home/{user}/.git/config",
    "env_file": "/home/{user}/.env",
    "ssh_key": "/home/{user}/.ssh/id_rsa",
    "aws_creds": "/home/{user}/.aws/credentials",
    "honeydoc": "/home/{user}/Documents/quarterly_report.docx",
}

_WINDOWS_DEFAULTS: dict[str, str] = {
    "git_config": "/home/{user}/AppData/Local/Programs/Git/etc/gitconfig",
    "env_file": "/home/{user}/Desktop/prod.env",
    "ssh_key": "/home/{user}/.ssh/id_rsa",  # OpenSSH on Windows uses the same path
    "aws_creds": "/home/{user}/.aws/credentials",
    "honeydoc": "/home/{user}/Documents/quarterly_report.docx",
}


def default_user(persona: str) -> str:
    """Return the conventional unprivileged username for a persona."""
    return DEFAULT_WINDOWS_USER if persona == "windows" else DEFAULT_LINUX_USER


def default_path_for(generator: str, persona: str = "linux") -> str:
    """Resolve the default placement path for a synthesized token.

    Returns an absolute container path with ``{user}`` already
    expanded.  Falls back to a sane Linux default for unknown
    personas — better to plant *something* than fail the deploy hook.
    """
    table = _WINDOWS_DEFAULTS if persona == "windows" else _LINUX_DEFAULTS
    template = table.get(generator)
    if not template:
        # Unknown generator — fall back to a generic /tmp drop so the
        # planter still has somewhere to write.  The API rejects
        # unknown generators upstream, so this branch is defensive.
        return f"/tmp/{generator}.canary"  # nosec B108 — placement inside attacker-facing decoy container, not host /tmp
    return template.format(user=default_user(persona))


def normalize_placement(path: str) -> str:
    """Validate and normalize an operator-supplied placement path.

    Forbids relative paths, NUL bytes, and shell metacharacters that
    ``docker exec sh -c`` can't safely round-trip.  Returns the
    sanitised path unchanged when valid; raises :class:`ValueError`
    otherwise so the API can return a 400 with a clear message.
    """
    if not path or not path.startswith("/"):
        raise ValueError("placement_path must be absolute (start with '/')")
    if "\x00" in path:
        raise ValueError("placement_path may not contain NUL")
    if "\n" in path or "\r" in path:
        raise ValueError("placement_path may not contain newlines")
    if "../" in path or path.endswith("/.."):
        raise ValueError("placement_path may not contain '..' segments")
    return path
