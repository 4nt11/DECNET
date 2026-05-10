#!/bin/bash
set -e

TLS_DIR="/opt/tls"
mkdir -p "$TLS_DIR"

# TLS_CERT/TLS_KEY may arrive as either a host-side path OR raw PEM content.
# Detect by looking for a PEM header; if present, write to disk.
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

# Parse HTTP_VERSIONS JSON → Caddy protocol tokens (h1 / h2 / h3)
CADDY_PROTOCOLS=$(python3 -c "
import json, os
versions = json.loads(os.environ.get('HTTP_VERSIONS', '[\"http/1.1\"]'))
tokens = []
if 'http/1.1' in versions:
    tokens.append('h1')
if 'http/2' in versions:
    tokens.append('h2')
if 'http/3' in versions:
    tokens.append('h3')
print(' '.join(tokens) if tokens else 'h1')
")

cat > /etc/caddy/Caddyfile <<EOF
{
  admin off
  servers :443 {
    protocols ${CADDY_PROTOCOLS}
  }
}

:443 {
  tls ${CERT} ${KEY}
  reverse_proxy 127.0.0.1:8080
}
EOF

python3 /opt/server.py &

# Wait for Flask to be ready before handing off to Caddy
python3 -c "
import socket, time
for _ in range(40):
    try:
        s = socket.create_connection(('127.0.0.1', 8080), timeout=0.25)
        s.close()
        break
    except OSError:
        time.sleep(0.1)
"

exec caddy run --config /etc/caddy/Caddyfile
