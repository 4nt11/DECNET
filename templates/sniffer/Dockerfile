ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages "scapy==2.6.1"

COPY decnet_logging.py server.py /opt/

ENTRYPOINT ["python3", "/opt/server.py"]
