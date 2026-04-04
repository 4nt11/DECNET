FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY imap_honeypot.py /opt/imap_honeypot.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 143 993
ENTRYPOINT ["/entrypoint.sh"]
