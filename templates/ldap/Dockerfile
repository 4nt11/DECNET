FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY ldap_honeypot.py /opt/ldap_honeypot.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 389 636
ENTRYPOINT ["/entrypoint.sh"]
