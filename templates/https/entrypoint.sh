#!/bin/bash
set -e

TLS_DIR="/opt/tls"
CERT="${TLS_CERT:-$TLS_DIR/cert.pem}"
KEY="${TLS_KEY:-$TLS_DIR/key.pem}"

# Generate a self-signed certificate if none exists
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    mkdir -p "$TLS_DIR"
    CN="${TLS_CN:-${NODE_NAME:-localhost}}"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY" -out "$CERT" \
        -days 3650 -subj "/CN=$CN" \
        2>/dev/null
fi

exec python3 /opt/server.py
