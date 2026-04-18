ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    rsyslog \
    curl \
    wget \
    vim \
    nano \
    net-tools \
    procps \
    htop \
    git \
    inotify-tools \
    psmisc \
    iproute2 \
    iputils-ping \
    ca-certificates \
    nmap \
    jq \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /root/.ssh /var/log/journal /var/lib/systemd/coredump \
    && chmod 700 /var/lib/systemd/coredump

# sshd_config: allow root + password auth; VERBOSE so session lines carry
# client IP + session PID (needed for file-capture attribution).
RUN sed -i \
    -e 's|^#\?PermitRootLogin.*|PermitRootLogin yes|' \
    -e 's|^#\?PasswordAuthentication.*|PasswordAuthentication yes|' \
    -e 's|^#\?ChallengeResponseAuthentication.*|ChallengeResponseAuthentication no|' \
    -e 's|^#\?LogLevel.*|LogLevel VERBOSE|' \
    /etc/ssh/sshd_config

# rsyslog: forward auth.* and user.* to PID 1's stdout in RFC 5424 format.
# /proc/1/fd/1 is the container-stdout fd Docker attached — writing there
# surfaces lines in `docker logs` without needing a named pipe + relay cat
# (which would be readable AND writable by any root-in-container process).
RUN printf '%s\n' \
    '# auth + user events → container stdout as RFC 5424' \
    '$template RFC5424fmt,"<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% %STRUCTURED-DATA% %msg%\n"' \
    'auth,authpriv.*  /proc/1/fd/1;RFC5424fmt' \
    'user.*           /proc/1/fd/1;RFC5424fmt' \
    > /etc/rsyslog.d/50-journal-forward.conf

# Silence default catch-all rules so we own auth/user routing exclusively
RUN sed -i \
    -e 's|^\(\*\.\*;auth,authpriv\.none\)|#\1|' \
    -e 's|^auth,authpriv\.\*|#auth,authpriv.*|' \
    /etc/rsyslog.conf

# Sudo: log to syslog (auth facility) AND a local file with full I/O capture
RUN echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers && \
    echo 'Defaults syslog=auth'                >> /etc/sudoers && \
    echo 'Defaults log_input,log_output'       >> /etc/sudoers

# Lived-in environment: motd, shell aliases, fake project files
RUN echo "Ubuntu 22.04.3 LTS" > /etc/issue.net && \
    echo "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)" > /etc/motd && \
    echo "" >> /etc/motd && \
    echo " * Documentation:  https://help.ubuntu.com" >> /etc/motd && \
    echo " * Management:     https://landscape.canonical.com" >> /etc/motd && \
    echo " * Support:        https://ubuntu.com/advantage" >> /etc/motd

RUN echo 'alias ll="ls -alF"' >> /root/.bashrc && \
    echo 'alias la="ls -A"'   >> /root/.bashrc && \
    echo 'alias l="ls -CF"'   >> /root/.bashrc && \
    echo 'export HISTSIZE=1000' >> /root/.bashrc && \
    echo 'export HISTFILESIZE=2000' >> /root/.bashrc && \
    echo 'PROMPT_COMMAND='"'"'logger -p user.info -t bash "CMD uid=$UID user=$USER src=${SSH_CLIENT%% *} pwd=$PWD cmd=$(history 1 | sed "s/^ *[0-9]* *//")";'"'" >> /root/.bashrc

# Fake project files to look lived-in
RUN mkdir -p /root/projects /root/backups /var/www/html && \
    printf '# TODO: migrate DB to new server\n# check cron jobs\n# update SSL cert\n' > /root/notes.txt && \
    printf 'DB_HOST=10.0.0.5\nDB_USER=admin\nDB_PASS=changeme123\nDB_NAME=prod_db\n' > /root/projects/.env && \
    printf '[Unit]\nDescription=App Server\n[Service]\nExecStart=/usr/bin/python3 /opt/app/server.py\n' > /root/projects/app.service

COPY entrypoint.sh /entrypoint.sh
# Capture machinery is installed under plausible systemd/udev paths so casual
# `ps aux` inspection doesn't scream "honeypot". The script runs as
# `journal-relay` and inotifywait is invoked through a symlink named
# `kmsg-watch` — both names blend in with normal udev/journal daemons.
COPY capture.sh /usr/libexec/udev/journal-relay

# argv_zap.so: LD_PRELOAD shim that blanks argv[1..] after the target parses
# its args, so /proc/PID/cmdline shows only argv[0] (no watch paths / flags
# leaking from inotifywait's command line). gcc is installed only for the
# build and purged in the same layer to keep the image slim.
COPY argv_zap.c /tmp/argv_zap.c
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && gcc -O2 -fPIC -shared -o /usr/lib/argv_zap.so /tmp/argv_zap.c -ldl \
    && apt-get purge -y gcc libc6-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/argv_zap.c

RUN mkdir -p /usr/libexec/udev \
    && chmod +x /entrypoint.sh /usr/libexec/udev/journal-relay \
    && ln -sf /usr/bin/inotifywait /usr/libexec/udev/kmsg-watch

EXPOSE 22

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD kill -0 1 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
