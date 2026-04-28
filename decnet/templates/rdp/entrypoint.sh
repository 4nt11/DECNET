#!/bin/bash
set -e

# Generate a self-signed cert on first start when NLA is enabled.
# Used by the CredSSP path to terminate the TLS layer that wraps NTLMSSP.
if [ "${RDP_ENABLE_NLA:-}" = "true" ] || [ "${RDP_ENABLE_NLA:-}" = "1" ]; then
    TLS_DIR="/opt/tls"
    CERT="${TLS_CERT:-$TLS_DIR/cert.pem}"
    KEY="${TLS_KEY:-$TLS_DIR/key.pem}"
    if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
        mkdir -p "$TLS_DIR"
        CN="${TLS_CN:-${NODE_NAME:-localhost}}"
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$KEY" -out "$CERT" \
            -days 3650 -subj "/CN=$CN" \
            2>/dev/null
    fi
fi

exec python3 /opt/server.py
