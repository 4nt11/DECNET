ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv \
    libssl-dev libffi-dev \
    git authbind \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash cowrie

WORKDIR /home/cowrie
RUN python3 -m venv cowrie-env \
    && cowrie-env/bin/pip install --no-cache-dir cowrie jinja2

# Authbind to bind port 22 as non-root
RUN touch /etc/authbind/byport/22 /etc/authbind/byport/2222 \
    && chmod 500 /etc/authbind/byport/22 /etc/authbind/byport/2222 \
    && chown cowrie /etc/authbind/byport/22 /etc/authbind/byport/2222

RUN mkdir -p /home/cowrie/cowrie-env/etc \
             /home/cowrie/cowrie-env/var/log/cowrie \
             /home/cowrie/cowrie-env/var/run \
    && chown -R cowrie /home/cowrie/cowrie-env/etc \
                       /home/cowrie/cowrie-env/var

COPY cowrie.cfg.j2 /home/cowrie/cowrie.cfg.j2
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER cowrie
EXPOSE 22 2222
ENTRYPOINT ["/entrypoint.sh"]
