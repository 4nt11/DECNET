"""Self-updater uvicorn launcher.

Parallels ``decnet/agent/server.py`` but uses a distinct bundle directory
(``~/.decnet/updater``) with a cert whose CN is ``updater@<host>``. That
cert is signed by the same DECNET CA as the agent's, so the master's one
CA still gates both channels; the CN is how we tell them apart.
"""
from __future__ import annotations

import os
import pathlib
import signal
import subprocess  # nosec B404
import sys

from decnet.logging import get_logger
from decnet.swarm import pki

log = get_logger("updater.server")

DEFAULT_UPDATER_DIR = pathlib.Path(os.path.expanduser("~/.decnet/updater"))


def _load_bundle(updater_dir: pathlib.Path) -> bool:
    return all(
        (updater_dir / name).is_file()
        for name in ("ca.crt", "updater.crt", "updater.key")
    )


def run(
    host: str,
    port: int,
    updater_dir: pathlib.Path = DEFAULT_UPDATER_DIR,
    install_dir: pathlib.Path = pathlib.Path("/opt/decnet"),
    agent_dir: pathlib.Path = pki.DEFAULT_AGENT_DIR,
) -> int:
    if not _load_bundle(updater_dir):
        print(
            f"[updater] No cert bundle at {updater_dir}. "
            f"Run `decnet swarm enroll --updater` from the master first.",
            file=sys.stderr,
        )
        return 2

    # Pass config into the app module via env so uvicorn subprocess picks it up.
    os.environ["DECNET_UPDATER_INSTALL_DIR"] = str(install_dir)
    os.environ["DECNET_UPDATER_UPDATER_DIR"] = str(install_dir / "updater")
    os.environ["DECNET_UPDATER_AGENT_DIR"] = str(agent_dir)

    keyfile = updater_dir / "updater.key"
    certfile = updater_dir / "updater.crt"
    cafile = updater_dir / "ca.crt"

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "decnet.updater.app:app",
        "--host",
        host,
        "--port",
        str(port),
        "--ssl-keyfile",
        str(keyfile),
        "--ssl-certfile",
        str(certfile),
        "--ssl-ca-certs",
        str(cafile),
        "--ssl-cert-reqs",
        "2",
    ]
    log.info("updater starting host=%s port=%d bundle=%s", host, port, updater_dir)
    proc = subprocess.Popen(cmd, start_new_session=True)  # nosec B603
    try:
        return proc.wait()
    except KeyboardInterrupt:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                return proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                return proc.wait()
        except ProcessLookupError:
            return 0
