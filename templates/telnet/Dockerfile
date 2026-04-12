ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    busybox-static \
    rsyslog \
    procps \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# rsyslog: forward auth.* and user.* to named pipe in RFC 5424 format
RUN printf '%s\n' \
    '# DECNET log bridge — auth + user events → named pipe as RFC 5424' \
    '$template RFC5424fmt,"<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% %STRUCTURED-DATA% %msg%\n"' \
    'auth,authpriv.*  |/var/run/decnet-logs;RFC5424fmt' \
    'user.*           |/var/run/decnet-logs;RFC5424fmt' \
    > /etc/rsyslog.d/99-decnet.conf

# Disable imklog — containers can't read /proc/kmsg
RUN sed -i 's/^\(module(load="imklog"\)/# \1/' /etc/rsyslog.conf

# Silence default catch-all rules
RUN sed -i \
    -e 's|^\(\*\.\*;auth,authpriv\.none\)|#\1|' \
    -e 's|^auth,authpriv\.\*|#auth,authpriv.*|' \
    /etc/rsyslog.conf

# Realistic motd and issue banner
RUN echo "Ubuntu 20.04.6 LTS" > /etc/issue.net && \
    echo "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)" > /etc/motd && \
    echo "" >> /etc/motd && \
    echo " * Documentation:  https://help.ubuntu.com" >> /etc/motd

# Fake lived-in files
RUN mkdir -p /root/scripts /root/backups && \
    printf '#!/bin/bash\n# DB backup script\nmysqldump -u root -padmin prod_db > /root/backups/db.sql\n' > /root/scripts/backup.sh && \
    printf 'DB_HOST=10.0.0.5\nDB_USER=admin\nDB_PASS=changeme123\n' > /root/.env && \
    printf 'alias ll="ls -alF"\nalias la="ls -A"\nexport HISTSIZE=1000\n' >> /root/.bashrc

# Log bash commands via syslog
RUN echo 'PROMPT_COMMAND='"'"'logger -p user.info -t bash "CMD uid=$UID pwd=$PWD cmd=$(history 1 | sed "s/^ *[0-9]* *//")";'"'" >> /root/.bashrc

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 23

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD kill -0 1 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
