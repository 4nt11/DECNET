#!/bin/bash
set -e

TLS_DIR="/opt/tls"
mkdir -p "$TLS_DIR"

# TLS_CERT/TLS_KEY may arrive as either a host-side path OR raw PEM
# content (the wizard ships PEM textareas as decoded strings). Detect by
# looking for a PEM header; if present, write to disk and rebind the var
# to the on-disk path.
if [ -n "$TLS_CERT" ] && printf '%s' "$TLS_CERT" | grep -q 'BEGIN '; then
    printf '%s' "$TLS_CERT" > "$TLS_DIR/cert.pem"
    CERT="$TLS_DIR/cert.pem"
else
    CERT="${TLS_CERT:-$TLS_DIR/cert.pem}"
fi
if [ -n "$TLS_KEY" ] && printf '%s' "$TLS_KEY" | grep -q 'BEGIN '; then
    printf '%s' "$TLS_KEY" > "$TLS_DIR/key.pem"
    chmod 600 "$TLS_DIR/key.pem"
    KEY="$TLS_DIR/key.pem"
else
    KEY="${TLS_KEY:-$TLS_DIR/key.pem}"
fi

# Generate a self-signed certificate if none exists
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    CN="${TLS_CN:-${NODE_NAME:-localhost}}"
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$KEY" -out "$CERT" \
        -days 3650 -subj "/CN=$CN" \
        2>/dev/null
fi

# server.py reads TLS_CERT/TLS_KEY as filesystem paths.
export TLS_CERT="$CERT"
export TLS_KEY="$KEY"

exec python3 /opt/server.py
