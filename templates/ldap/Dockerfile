ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY syslog_bridge.py /opt/syslog_bridge.py
COPY server.py /opt/server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 389 636
RUN useradd -r -s /bin/false -d /opt logrelay \
 && apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
 && rm -rf /var/lib/apt/lists/* \
 && (find /usr/bin/ -maxdepth 1 -name 'python3*' -type f -exec setcap 'cap_net_bind_service+eip' {} \; 2>/dev/null || true)

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD kill -0 1 || exit 1

USER logrelay
ENTRYPOINT ["/entrypoint.sh"]
