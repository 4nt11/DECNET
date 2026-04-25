ARG BASE_IMAGE=debian:bookworm-slim

# ── Stage 1: build the static auth-helper credential-capture binary ──────────
# Compiled against musl so the resulting binary is fully static — runs on
# any glibc/musl Linux without a libc version match. Stripped at link
# time via -s so `file /usr/sbin/auth-helper` reports a generic ELF.
FROM debian:bookworm-slim AS auth-helper-build
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*
COPY auth-helper.c /tmp/auth-helper.c
RUN musl-gcc -static -O2 -s -Wall -Wextra \
    -o /auth-helper /tmp/auth-helper.c

# ── Stage 2: the actual SSH decky image ──────────────────────────────────────
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
    python3 \
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

# Silence default catch-all rules so we own auth/user routing exclusively.
# Also disable rsyslog's privilege drop: PID 1's stdout (/proc/1/fd/1) is
# owned by root, so a syslog-user rsyslogd gets EACCES and silently drops
# every auth/user line (bash CMD events + file_captured emissions).
RUN sed -i \
    -e 's|^\(\*\.\*;auth,authpriv\.none\)|#\1|' \
    -e 's|^auth,authpriv\.\*|#auth,authpriv.*|' \
    -e 's|^\$PrivDropToUser|#$PrivDropToUser|' \
    -e 's|^\$PrivDropToGroup|#$PrivDropToGroup|' \
    /etc/rsyslog.conf

# auth-helper: drop the static binary into /usr/sbin and wire pam_exec
# into the sshd PAM stack so every password attempt (success or fail) is
# captured before pam_unix runs. `optional` so a malfunctioning helper
# never blocks auth — fail-open is correct: missed creds are recoverable,
# a borked honeypot is not. expose_authtok writes the password to the
# helper's stdin, NUL-terminated.
COPY --from=auth-helper-build /auth-helper /usr/sbin/auth-helper
RUN chmod 755 /usr/sbin/auth-helper && \
    sed -i '1i auth optional pam_exec.so expose_authtok stdout /usr/sbin/auth-helper' \
        /etc/pam.d/sshd

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

# Stage all capture sources in a scratch dir. Nothing here survives the layer:
# _build_stealth.py packs syslog_bridge.py + emit_capture.py + capture.sh into
# XOR+gzip+base64 blobs embedded directly in /entrypoint.sh, and the whole
# /tmp/build tree is wiped at the end of the RUN — so the final image has no
# `.py` file under /opt and no `journal-relay` script under /usr/libexec/udev.
COPY entrypoint.sh capture.sh syslog_bridge.py emit_capture.py \
     argv_zap.c _build_stealth.py /tmp/build/
COPY sessrec/ /tmp/build/sessrec/

# argv_zap is compiled into a shared object disguised as a multiarch
# udev-companion library (sits next to real libudev.so.1). sessrec is built
# as /usr/libexec/login-session, installed as root's login shell so every
# interactive SSH session is pty-recorded. gcc is installed only for this
# build step and purged in the same layer.
RUN set -eu \
    && apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev make \
    && mkdir -p /usr/lib/x86_64-linux-gnu /usr/libexec/udev /usr/libexec \
    && gcc -O2 -fPIC -shared \
        -o /usr/lib/x86_64-linux-gnu/libudev-shared.so.1 \
        /tmp/build/argv_zap.c -ldl \
    && make -C /tmp/build/sessrec install PREFIX=/usr/libexec \
    && grep -q '^/usr/libexec/login-session$' /etc/shells \
        || echo '/usr/libexec/login-session' >> /etc/shells \
    && sed -i 's|^root:\([^:]*\):\([^:]*\):\([^:]*\):\([^:]*\):\([^:]*\):.*$|root:\1:\2:\3:\4:\5:/usr/libexec/login-session|' /etc/passwd \
    && apt-get purge -y gcc libc6-dev make \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/inotifywait /usr/libexec/udev/kmsg-watch \
    && python3 /tmp/build/_build_stealth.py \
    && rm -rf /tmp/build

EXPOSE 22

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD kill -0 1 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
