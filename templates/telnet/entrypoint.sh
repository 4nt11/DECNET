#!/bin/bash
set -e

# Configure root password (default: admin)
ROOT_PASSWORD="${TELNET_ROOT_PASSWORD:-admin}"
echo "root:${ROOT_PASSWORD}" | chpasswd

# Optional: override hostname inside container
if [ -n "$TELNET_HOSTNAME" ]; then
    echo "$TELNET_HOSTNAME" > /etc/hostname
    hostname "$TELNET_HOSTNAME"
fi

# Fake bash history so the box looks used
if [ ! -f /root/.bash_history ]; then
    cat > /root/.bash_history <<'HIST'
apt update && apt upgrade -y
systemctl status mysql
tail -f /var/log/syslog
df -h
ps aux
cd /root/scripts
bash backup.sh
crontab -e
ls /root/backups
cat /root/.env
HIST
fi

# Logging pipeline: named pipe → rsyslogd (RFC 5424) → stdout
rm -f /var/run/decnet-logs
mkfifo /var/run/decnet-logs

# Relay pipe to stdout so Docker captures all syslog events
cat /var/run/decnet-logs &

# Start rsyslog
rsyslogd

# busybox telnetd: foreground mode, real /bin/login for PAM auth logging
exec busybox telnetd -F -l /bin/login -p 23
