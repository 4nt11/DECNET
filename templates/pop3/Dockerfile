FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY pop3_honeypot.py /opt/pop3_honeypot.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 110 995
ENTRYPOINT ["/entrypoint.sh"]
