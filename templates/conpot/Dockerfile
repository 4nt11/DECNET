ARG BASE_IMAGE=honeynet/conpot:latest
FROM ${BASE_IMAGE}

USER root

# Temporary fix: Conpot's default config binds Modbus to a non-privileged port (like 5020).
# DECNET requires it to bind directly to 502 for the honeypot to work as expected.
# We search the template directories and replace the port configuration.
# This is a temporary fix pending an upstream PR from the Conpot maintainers.
RUN find /opt /usr /etc /home -name "*.xml" -exec sed -i 's/<port>5020<\/port>/<port>502<\/port>/g' {} + 2>/dev/null || true
RUN find /opt /usr /etc /home -name "*.xml" -exec sed -i 's/port="5020"/port="502"/g' {} + 2>/dev/null || true

# Switching back to the internal user if standard in conpot (falling back to nobody/conpot as appropriate)
# End of Dockerfile
