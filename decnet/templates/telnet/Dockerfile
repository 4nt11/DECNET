ARG BASE_IMAGE=debian:bookworm-slim

# ── Stage 1: build the static auth-helper credential-capture binary ──────────
# Same source the SSH template builds — generic over PAM service. Wired
# into /etc/pam.d/login below so every busybox-telnetd → /bin/login auth
# attempt is captured before pam_unix runs. Static + musl: ~38 KB ELF,
# zero libc version coupling, runs anywhere.
FROM debian:bookworm-slim AS auth-helper-build
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*
COPY auth-helper/auth-helper.c /tmp/auth-helper.c
RUN musl-gcc -static -O2 -s -Wall -Wextra \
    -o /auth-helper /tmp/auth-helper.c

# ── Stage 2: the actual telnet decky image ───────────────────────────────────
FROM ${BASE_IMAGE}

# `login` (real Debian /bin/login, PAM-aware) replaces busybox's PAM-less
# login applet. libpam-modules ships pam_exec.so transitively. Both are
# needed for the auth-helper hook to fire — without them the PAM stack
# can't load pam_exec or call into a real PAM service.
RUN apt-get update && apt-get install -y --no-install-recommends \
    busybox-static \
    login \
    libpam-modules \
    rsyslog \
    procps \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# sessrec (pty transcript recorder) becomes root's login shell so busybox
# /bin/login exec's it after PAM auth. gcc + libc6-dev are installed only
# for this compile step and purged in the same layer.
COPY sessrec/ /tmp/build/sessrec/
RUN set -eu \
    && apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev make \
    && mkdir -p /usr/libexec \
    && make -C /tmp/build/sessrec install PREFIX=/usr/libexec \
    && grep -q '^/usr/libexec/login-session$' /etc/shells \
        || echo '/usr/libexec/login-session' >> /etc/shells \
    && sed -i 's|^root:\([^:]*\):\([^:]*\):\([^:]*\):\([^:]*\):\([^:]*\):.*$|root:\1:\2:\3:\4:\5:/usr/libexec/login-session|' /etc/passwd \
    && apt-get purge -y gcc libc6-dev make \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* /tmp/build

# rsyslog: forward auth.* and user.* to named pipe in RFC 5424 format
RUN printf '%s\n' \
    '# syslog-relay log bridge — auth + user events → named pipe as RFC 5424' \
    '$template RFC5424fmt,"<%PRI%>1 %TIMESTAMP:::date-rfc3339% %HOSTNAME% %APP-NAME% %PROCID% %MSGID% %STRUCTURED-DATA% %msg%\n"' \
    'auth,authpriv.*  |/run/systemd/journal/syslog-relay;RFC5424fmt' \
    'user.*           |/run/systemd/journal/syslog-relay;RFC5424fmt' \
    > /etc/rsyslog.d/50-journal-forward.conf

# Disable imklog — containers can't read /proc/kmsg
RUN sed -i 's/^\(module(load="imklog"\)/# \1/' /etc/rsyslog.conf

# Silence default catch-all rules
RUN sed -i \
    -e 's|^\(\*\.\*;auth,authpriv\.none\)|#\1|' \
    -e 's|^auth,authpriv\.\*|#auth,authpriv.*|' \
    /etc/rsyslog.conf

# auth-helper: drop the static binary into /usr/sbin and wire pam_exec
# into the login PAM stack so every busybox-telnetd password attempt
# (success or fail) is captured before pam_unix runs. Same `optional`
# fail-open semantics as the SSH template.
COPY --from=auth-helper-build /auth-helper /usr/sbin/auth-helper
RUN chmod 755 /usr/sbin/auth-helper && \
    sed -i '1i auth optional pam_exec.so expose_authtok stdout /usr/sbin/auth-helper' \
        /etc/pam.d/login

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

# Command-event capture. PROMPT_COMMAND is set in /etc/environment
# (read by pam_env at /bin/login session open, before any shell rc
# fires) and pinned readonly via /etc/bash.bashrc — `export
# PROMPT_COMMAND=""` fails with "readonly variable" instead of
# silently disabling capture. Function name is generic so a casual
# `set | grep PROMPT` doesn't surface DECNET branding.
RUN printf 'PROMPT_COMMAND=__bash_history_sync\n' >> /etc/environment \
 && printf '%s\n' \
    '# bash history → syslog, system-wide.' \
    '__bash_history_sync() {' \
    '    logger --rfc5424 --msgid command -p user.info -t bash "CMD uid=$UID pwd=$PWD cmd=$(history 1 | sed '"'"'s/^ *[0-9]* *//'"'"')"' \
    '}' \
    'readonly -f __bash_history_sync 2>/dev/null || true' \
    'readonly PROMPT_COMMAND 2>/dev/null || true' \
    >> /etc/bash.bashrc

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 23

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD kill -0 1 || exit 1

ENTRYPOINT ["/entrypoint.sh"]
