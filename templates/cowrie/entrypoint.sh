#!/bin/bash
set -e

# Render Jinja2 config template
/home/cowrie/cowrie-env/bin/python3 - <<'EOF'
import os
from jinja2 import Template

with open("/home/cowrie/cowrie.cfg.j2") as f:
    tpl = Template(f.read())

rendered = tpl.render(**os.environ)

with open("/home/cowrie/cowrie-env/etc/cowrie.cfg", "w") as f:
    f.write(rendered)
EOF

# Write userdb.txt if custom users were provided
# Format: COWRIE_USERDB_ENTRIES=root:toor,admin:admin123
if [ -n "${COWRIE_USERDB_ENTRIES}" ]; then
    USERDB="/home/cowrie/cowrie-env/etc/userdb.txt"
    : > "$USERDB"
    IFS=',' read -ra PAIRS <<< "${COWRIE_USERDB_ENTRIES}"
    for pair in "${PAIRS[@]}"; do
        user="${pair%%:*}"
        pass="${pair#*:}"
        uid=1000
        [ "$user" = "root" ] && uid=0
        echo "${user}:${uid}:${pass}" >> "$USERDB"
    done
fi

exec authbind --deep /home/cowrie/cowrie-env/bin/twistd -n --pidfile= cowrie
