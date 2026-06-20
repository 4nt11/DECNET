# Cloak base image — the IP-holder/netns container for deckies whose nmap_os has
# an egress mangle profile (windows, windows_server). Runs `python -m decnet.cloak`
# (SYN-ACK mangler + T2/T3 responder) alongside holding the MACVLAN IP.
#
# FROM the per-decky distro so the base still varies by distro (BASE_IMAGE arg,
# set by the composer from decky.build_base — same pattern as service images).
# The decnet/ subtree is synced into this context by deployer._sync_cloak_sources
# before build (8 light, stdlib-only files; scapy/netfilterqueue are pip'd here).
ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}

# Runtime: iptables (NFQUEUE rules), python3, libpcap (scapy BPF sniff in the
# responder). Build-only: gcc + headers for the netfilterqueue C extension,
# purged after the wheel is built to keep the image lean.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip iptables libpcap0.8 \
        libnetfilter-queue1 libnfnetlink0 \
        gcc python3-dev libnetfilter-queue-dev libnfnetlink-dev \
    && pip3 install --no-cache-dir --break-system-packages \
        "scapy>=2.6.1" "netfilterqueue>=1.1.0" \
    && apt-get purge -y gcc python3-dev libnetfilter-queue-dev libnfnetlink-dev \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Synced 8-file decnet subtree (decnet/__init__, config_ini, logging/, os_fingerprint,
# cloak/). PYTHONPATH=/opt makes `python3 -m decnet.cloak` importable.
COPY decnet/ /opt/decnet/
ENV PYTHONPATH=/opt

# The compose `command` drives runtime (netns-safe supervisor: cloak in background,
# sleep infinity in foreground so a cloak crash never tears down the netns holder).
CMD ["sleep", "infinity"]
