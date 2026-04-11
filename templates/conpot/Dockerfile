ARG BASE_IMAGE=honeynet/conpot:latest
FROM ${BASE_IMAGE}

USER root

# Replace 5020 with 502 in all templates so Modbus binds on the standard port
RUN find /opt /usr /etc /home -name "*.xml" -exec sed -i 's/<port>5020<\/port>/<port>502<\/port>/g' {} + 2>/dev/null || true
RUN find /opt /usr /etc /home -name "*.xml" -exec sed -i 's/port="5020"/port="502"/g' {} + 2>/dev/null || true

# Install libcap and give the Python interpreter permission to bind ports < 1024
RUN (apt-get update && apt-get install -y --no-install-recommends libcap2-bin 2>/dev/null) || (apk add --no-cache libcap 2>/dev/null) || true
RUN find /home/conpot/.local/bin /usr /opt -type f -name 'python*' -exec setcap 'cap_net_bind_service+eip' {} \; 2>/dev/null || true

# The upstream image already runs as the non-root 'conpot' user.
# We do NOT switch to a 'decnet' user here — doing so breaks pkg_resources
# because conpot's eggs live under /home/conpot/.local and are only on the
# Python path when the interpreter runs as 'conpot'.
USER conpot
