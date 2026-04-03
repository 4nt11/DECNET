#!/bin/bash
set -e

# Render Jinja2 template using the venv's python (has jinja2)
/home/cowrie/cowrie-env/bin/python3 - <<'EOF'
import os
from jinja2 import Template

with open("/home/cowrie/cowrie.cfg.j2") as f:
    tpl = Template(f.read())

rendered = tpl.render(**os.environ)

with open("/home/cowrie/cowrie-env/etc/cowrie.cfg", "w") as f:
    f.write(rendered)
EOF

exec authbind --deep /home/cowrie/cowrie-env/bin/twistd -n --pidfile= cowrie
