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
rsyslogd

# File-catcher: mirror attacker drops into host-mounted quarantine with attribution.
# Script lives at /usr/libexec/udev/journal-relay so `ps aux` shows a
# plausible udev helper. See Dockerfile for the rename rationale.
# LD_PRELOAD + ARGV_ZAP_COMM blank bash's argv[1..] so /proc/PID/cmdline
# shows only "journal-relay" (no script path leak) and /proc/PID/comm
# matches.
CAPTURE_DIR=/var/lib/systemd/coredump \
LD_PRELOAD=/usr/lib/argv_zap.so \
ARGV_ZAP_COMM=journal-relay \
    bash -c 'exec -a "journal-relay" bash /usr/libexec/udev/journal-relay' &

# sshd logs via syslog — no -e flag, so auth events flow through rsyslog → pipe → stdout
exec /usr/sbin/sshd -D
