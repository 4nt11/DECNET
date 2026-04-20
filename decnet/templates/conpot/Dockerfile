ARG BASE_IMAGE=honeynet/conpot:latest
FROM ${BASE_IMAGE}

USER root

# Replace 5020 with 502 in all templates so Modbus binds on the standard port
RUN find /opt /usr /etc /home -name "*.xml" -exec sed -i 's/<port>5020<\/port>/<port>502<\/port>/g' {} + 2>/dev/null || true
RUN find /opt /usr /etc /home -name "*.xml" -exec sed -i 's/port="5020"/port="502"/g' {} + 2>/dev/null || true

# Install libcap and give the Python interpreter permission to bind ports < 1024
RUN (apt-get update && apt-get install -y --no-install-recommends libcap2-bin 2>/dev/null) || (apk add --no-cache libcap 2>/dev/null) || true
RUN find /home/conpot/.local/bin /usr /opt -type f -name 'python*' -exec setcap 'cap_net_bind_service+eip' {} \; 2>/dev/null || true

# Bridge conpot's own logger into syslog-relay's RFC 5424 syslog pipeline.
# entrypoint.py is self-contained (inlines the formatter) because the
# conpot base image runs Python 3.6, which cannot import the shared
# syslog_bridge.py (that file uses 3.9+ / 3.10+ type syntax).
COPY entrypoint.py /home/conpot/entrypoint.py
RUN chown conpot:conpot /home/conpot/entrypoint.py \
    && chmod +x /home/conpot/entrypoint.py

# The upstream image already runs as non-root 'conpot'.
# We do NOT switch to a 'logrelay' user — doing so breaks pkg_resources
# because conpot's eggs live under /home/conpot/.local and are only on
# the Python path for that user.
USER conpot

ENTRYPOINT ["/usr/bin/python3", "/home/conpot/entrypoint.py"]
