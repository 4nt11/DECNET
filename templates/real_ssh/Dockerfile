ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    curl \
    wget \
    vim \
    nano \
    net-tools \
    procps \
    htop \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd /root/.ssh

# sshd_config: allow root + password auth
RUN sed -i \
    -e 's|^#\?PermitRootLogin.*|PermitRootLogin yes|' \
    -e 's|^#\?PasswordAuthentication.*|PasswordAuthentication yes|' \
    -e 's|^#\?ChallengeResponseAuthentication.*|ChallengeResponseAuthentication no|' \
    /etc/ssh/sshd_config

# Lived-in environment: motd, shell aliases, fake project files
RUN echo "Ubuntu 22.04.3 LTS" > /etc/issue.net && \
    echo "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)" > /etc/motd && \
    echo "" >> /etc/motd && \
    echo " * Documentation:  https://help.ubuntu.com" >> /etc/motd && \
    echo " * Management:     https://landscape.canonical.com" >> /etc/motd && \
    echo " * Support:        https://ubuntu.com/advantage" >> /etc/motd

RUN echo 'alias ll="ls -alF"' >> /root/.bashrc && \
    echo 'alias la="ls -A"' >> /root/.bashrc && \
    echo 'alias l="ls -CF"' >> /root/.bashrc && \
    echo 'export HISTSIZE=1000' >> /root/.bashrc && \
    echo 'export HISTFILESIZE=2000' >> /root/.bashrc

# Fake project files to look lived-in
RUN mkdir -p /root/projects /root/backups /var/www/html && \
    echo "# TODO: migrate DB to new server\n# check cron jobs\n# update SSL cert" > /root/notes.txt && \
    echo "DB_HOST=10.0.0.5\nDB_USER=admin\nDB_PASS=changeme123\nDB_NAME=prod_db" > /root/projects/.env && \
    echo "[Unit]\nDescription=App Server\n[Service]\nExecStart=/usr/bin/python3 /opt/app/server.py" > /root/projects/app.service

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

RUN useradd -r -s /bin/false -d /opt decnet \
 && apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
 && rm -rf /var/lib/apt/lists/* \
 && find /usr/bin/python3* -maxdepth 0 -type f -exec setcap 'cap_net_bind_service+eip' {} \;

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD kill -0 1 || exit 1

USER decnet
ENTRYPOINT ["/entrypoint.sh"]
