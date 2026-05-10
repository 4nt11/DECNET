#!/bin/bash
set -e

# Parse HTTP_VERSIONS JSON → Caddy protocol tokens (h1 / h2c)
CADDY_PROTOCOLS=$(python3 -c "
import json, os
versions = json.loads(os.environ.get('HTTP_VERSIONS', '[\"http/1.1\"]'))
tokens = []
if 'http/1.1' in versions:
    tokens.append('h1')
if 'http/2' in versions:
    tokens.append('h2c')
print(' '.join(tokens) if tokens else 'h1')
")

DECNET_FP_SOCK="${DECNET_FP_SOCK:-/run/decnet/fp.sock}"
rm -f "$DECNET_FP_SOCK"

cat > /etc/caddy/Caddyfile <<EOF
{
  admin off
  servers :80 {
    protocols ${CADDY_PROTOCOLS}
  }
}

:80 {
  route {
    decnet_fp
    reverse_proxy 127.0.0.1:8080
  }
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
