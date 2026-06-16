# SPDX-License-Identifier: AGPL-3.0-or-later
"""Worker-agent uvicorn launcher.

Starts ``decnet.agent.app:app`` over HTTPS with mTLS enforcement.  The
worker must already have a bundle in ``~/.decnet/agent/`` (delivered by
``decnet swarm enroll`` from the master); if it does not, we refuse to
start — unauthenticated agents are not a supported mode.
"""
from __future__ import annotations

import os
import pathlib
import signal
import subprocess  # nosec B404
import sys

from decnet.logging import get_logger
from decnet.swarm import pki

log = get_logger("agent.server")


def run(host: str, port: int, agent_dir: pathlib.Path = pki.DEFAULT_AGENT_DIR) -> int:
    bundle = pki.load_worker_bundle(agent_dir)
    if bundle is None:
        print(
            f"[agent] No cert bundle at {agent_dir}. "
            f"Run `decnet swarm enroll` from the master first.",
            file=sys.stderr,
        )
        return 2

    keyfile = agent_dir / "worker.key"
    certfile = agent_dir / "worker.crt"
    cafile = agent_dir / "ca.crt"

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "decnet.agent.app:app",
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
        # 2 == ssl.CERT_REQUIRED — clients MUST present a CA-signed cert.
        "--ssl-cert-reqs",
        "2",
    ]
    log.info("agent starting host=%s port=%d bundle=%s", host, port, agent_dir)
    # Own process group for clean Ctrl+C / SIGTERM propagation to uvicorn
    # workers (same pattern as `decnet api`).
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
