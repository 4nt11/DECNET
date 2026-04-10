ARG BASE_IMAGE=honeynet/conpot:latest
FROM ${BASE_IMAGE}

USER root

# Replace 5020 with 502 in all templates
RUN find /opt /usr /etc /home -name "*.xml" -exec sed -i 's/<port>5020<\/port>/<port>502<\/port>/g' {} + 2>/dev/null || true
RUN find /opt /usr /etc /home -name "*.xml" -exec sed -i 's/port="5020"/port="502"/g' {} + 2>/dev/null || true

# Install libcap to allow binding to 502
RUN (apt-get update && apt-get install -y --no-install-recommends libcap2-bin 2>/dev/null) || (apk add --no-cache libcap 2>/dev/null) || true

# Apply setcap to python binaries
RUN find /usr /opt -type f -name 'python*' -exec setcap 'cap_net_bind_service+eip' {} \; 2>/dev/null || true

# Create the decnet user following repository conventions
RUN (addgroup -S decnet && adduser -S decnet -G decnet 2>/dev/null) || useradd -r -s /bin/false decnet 2>/dev/null || true

# Make sure all conpot-related directories are owned by decnet so it can run it
RUN chown -R decnet:decnet /var/log/conpot /opt/conpot /home/conpot /usr/local/lib/python*/site-packages/conpot/tests/data /tmp 2>/dev/null || true

# Run as decnet user, avoiding the root-check failure and 777 hacks
USER decnet
