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

# sessrec needs the transcripts dir on the quarantine mount + a service
# discriminant file (busybox /bin/login strips env, so we can't rely on
# SESSREC_SERVICE env var here like the SSH template does).
mkdir -p /var/lib/systemd/coredump/transcripts
chmod 750 /var/lib/systemd/coredump/transcripts
echo "telnet" > /etc/sessrec.service

# Logging pipeline: named pipe → rsyslogd (RFC 5424) → stdout.
# Cloak the pipe path and the relay `cat` so `ps aux` / `ls /run` don't
# betray the honeypot — see ssh/entrypoint.sh for the same pattern.
mkdir -p /run/systemd/journal
rm -f /run/systemd/journal/syslog-relay
mkfifo /run/systemd/journal/syslog-relay

bash -c 'exec -a "systemd-journal-fwd" cat /run/systemd/journal/syslog-relay' &

# Start rsyslog
rsyslogd

# busybox telnetd: foreground mode, real /bin/login for PAM auth logging
exec busybox telnetd -F -l /bin/login -p 23
