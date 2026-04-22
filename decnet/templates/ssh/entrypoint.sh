#!/bin/bash
set -e

# Configure root password (default: admin)
ROOT_PASSWORD="${SSH_ROOT_PASSWORD:-admin}"
echo "root:${ROOT_PASSWORD}" | chpasswd

# Optional: override hostname inside container
if [ -n "$SSH_HOSTNAME" ]; then
    echo "$SSH_HOSTNAME" > /etc/hostname
    hostname "$SSH_HOSTNAME"
fi

# Generate host keys if missing (first boot)
ssh-keygen -A

# Ensure transcripts dir exists on the quarantine mount. sessrec appends to
# one JSONL day-shard per decky; PAM-seeded env vars tell it which service
# slot owns this container (used in the session_recorded syslog event).
mkdir -p /var/lib/systemd/coredump/transcripts
chmod 750 /var/lib/systemd/coredump/transcripts
echo "ssh" > /etc/sessrec.service
{
    echo "SESSREC_SERVICE=ssh"
    [ -n "${NODE_NAME:-}" ] && echo "NODE_NAME=${NODE_NAME}"
} >> /etc/environment

# Fake bash history so the box looks used
if [ ! -f /root/.bash_history ]; then
    cat > /root/.bash_history <<'HIST'
apt update && apt upgrade -y
systemctl status nginx
tail -f /var/log/syslog
df -h
htop
ps aux | grep python
git pull origin main
cd /root/projects
vim notes.txt
crontab -e
ls /var/www/html
HIST
fi

# Logging pipeline: rsyslogd (RFC 5424) → /proc/1/fd/1 → Docker log capture.
# No intermediate pipe/relay — a named FIFO would be readable AND writable
# by any root-in-container process, letting an attacker either eavesdrop on
# the SIEM feed or inject forged log lines.
if [ -n "${NODE_NAME:-}" ]; then
    printf '$LocalHostName %s\n' "$NODE_NAME" > /etc/rsyslog.d/00-localhostname.conf
fi
rsyslogd

# ─── systemd-journal companion bootstrap ─────────────────────────────────────
# The next block primes cached udev/journal helpers from in-memory tables.
# Tables are XOR+gzip+base64 packed at image build. Keeping the data inline
# avoids a separate /usr/libexec script (which would be visible and readable)
# and means the helpers only ever live in this process's memory + an
# anonymous pipe the kernel hands to python via /dev/fd.
_STEALTH_KEY=__STEALTH_KEY__
_EMIT_CAPTURE_B64='__EMIT_CAPTURE_B64__'
_JOURNAL_RELAY_B64='__JOURNAL_RELAY_B64__'

_decode() {
    printf '%s' "$1" | base64 -d | python3 -c '
import sys
k = '"$_STEALTH_KEY"'
d = sys.stdin.buffer.read()
sys.stdout.buffer.write(bytes(b ^ k for b in d))
' | gunzip
}

EMIT_CAPTURE_PY="$(_decode "$_EMIT_CAPTURE_B64")"
_JOURNAL_RELAY_SRC="$(_decode "$_JOURNAL_RELAY_B64")"
export EMIT_CAPTURE_PY
unset _EMIT_CAPTURE_B64 _JOURNAL_RELAY_B64 _STEALTH_KEY

# Launch the file-capture loop from memory. LD_PRELOAD + ARGV_ZAP_COMM blank
# argv[1..] so /proc/PID/cmdline shows only "journal-relay".
(
    export CAPTURE_DIR=/var/lib/systemd/coredump
    export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libudev-shared.so.1
    export ARGV_ZAP_COMM=journal-relay
    exec -a journal-relay bash -c "$_JOURNAL_RELAY_SRC"
) &

unset _JOURNAL_RELAY_SRC

# sshd logs via syslog — no -e flag, so auth events flow through rsyslog → /proc/1/fd/1 → stdout
exec /usr/sbin/sshd -D
