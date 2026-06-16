ARG BASE_IMAGE=debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252

FROM caddy:2-builder AS caddy-build
COPY _caddy_modules/decnetfp /src/decnetfp
RUN xcaddy build \
    --with github.com/decnet/caddy-fp=/src/decnetfp \
    --output /usr/bin/caddy

FROM ${BASE_IMAGE}

COPY --from=caddy-build /usr/bin/caddy /usr/bin/caddy

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN pip3 install --no-cache-dir flask jinja2

COPY syslog_bridge.py /opt/syslog_bridge.py
COPY instance_seed.py /opt/instance_seed.py
COPY server.py /opt/server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

RUN mkdir -p /run/decnet
RUN useradd -r -s /bin/false -d /opt logrelay \
 && chown -R logrelay:logrelay /run/decnet \
 && mkdir -p /etc/caddy /opt/.local/share/caddy /opt/.config/caddy \
 && chown -R logrelay:logrelay /etc/caddy /opt/.local /opt/.config \
 && apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
 && rm -rf /var/lib/apt/lists/* \
 && setcap 'cap_net_bind_service+eip' /usr/bin/caddy \
 && (find /usr/bin/ -maxdepth 1 -name 'python3*' -type f -exec setcap 'cap_net_bind_service+eip' {} \; 2>/dev/null || true)

ENV XDG_DATA_HOME=/opt/.local/share XDG_CONFIG_HOME=/opt/.config

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD kill -0 1 || exit 1

USER logrelay
ENTRYPOINT ["/entrypoint.sh"]
