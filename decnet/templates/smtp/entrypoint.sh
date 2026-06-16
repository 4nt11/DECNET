#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -e

# Fix quarantine dir permissions before dropping privileges — the dir is
# bind-mounted from the host (owned by the decnet user) and must be writable
# by the logrelay process inside the container.
if [ -n "$SMTP_QUARANTINE_DIR" ]; then
    mkdir -p "$SMTP_QUARANTINE_DIR"
    chmod 0777 "$SMTP_QUARANTINE_DIR"
fi

exec su -s /bin/sh logrelay -c "exec python3 /opt/server.py"
