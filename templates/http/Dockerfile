ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN pip3 install --no-cache-dir flask jinja2

COPY decnet_logging.py /opt/decnet_logging.py
COPY server.py /opt/server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 443
RUN useradd -r -s /bin/false -d /opt decnet \
 && apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
 && rm -rf /var/lib/apt/lists/* \
 && find /usr/bin/python3* -maxdepth 0 -type f -exec setcap 'cap_net_bind_service+eip' {} \;

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD kill -0 1 || exit 1

USER decnet
ENTRYPOINT ["/entrypoint.sh"]
