FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages flask

COPY docker_api_honeypot.py /opt/docker_api_honeypot.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 2375 2376
ENTRYPOINT ["/entrypoint.sh"]
