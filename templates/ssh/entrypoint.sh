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

# Logging pipeline: named pipe → rsyslogd (RFC 5424) → stdout → Docker log capture
mkfifo /var/run/decnet-logs

# Relay pipe to stdout so Docker captures all syslog events
cat /var/run/decnet-logs &

# Start rsyslog (reads /etc/rsyslog.d/99-decnet.conf, writes to the pipe above)
rsyslogd

# File-catcher: mirror attacker drops into host-mounted quarantine with attribution.
# Script lives at /usr/libexec/udev/journal-relay so `ps aux` shows a
# plausible udev helper. See Dockerfile for the rename rationale.
CAPTURE_DIR=/var/decnet/captured /usr/libexec/udev/journal-relay &

# sshd logs via syslog — no -e flag, so auth events flow through rsyslog → pipe → stdout
exec /usr/sbin/sshd -D
