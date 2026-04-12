# DECNET — Future Concepts & Architecture

This document tracks long-term, visionary architectural concepts and ideas that are outside the scope of the 1.0 roadmap, but represent the ultimate end-state of the DECNET framework.

## The Honeymaze: Spider Network Topology

### Concept Overview
As attackers breach the perimeter, instead of just lateral movement on a flat `/24` or massive VXLAN, DECNET can dynamically generate an infinite "daisy-chain" of isolated Docker networks. This forces the attacker to establish deep, nested C2 proxy chains (SOCKS, chisel, SSH tunnels) to pivot from machine to machine. 

For example:
- `decky-01` sits on the main LAN via `eth0` (MACVLAN). It also has `eth1`, which belongs to `docker-bridge-1`.
- `decky-02` sits exclusively on `docker-bridge-1` as its `eth0`. It also has `eth1`, belonging to `docker-bridge-2`.
- `decky-03` sits exclusively on `docker-bridge-2`.

### Strategic Value
1. **High-Fidelity TTP Telemetry**: By forcing the attacker into a corner where they *must* deploy pivot infrastructure, we capture extremely high-value indicators of compromise regarding their proxy tooling and network tradecraft.
2. **Infinite Time Sinks**: An attacker can spend weeks navigating simulated air-gaps and deep corporate enclaves feeling a false sense of progression.

### Execution & Realism Restrictions
To prevent the topology from feeling artificial or obviously simulated:
1. **Asymmetric Nesting**: A strict 1:1 nested daisy chain is a dead giveaway. Real corporate networks branch organically.
   - Some machines should be terminal endpoints (no nested subnets).
   - Some machines acts as jump hosts bridging two large local arrays.
   - The depth and horizontal fan-out per subnet must be randomized to emulate realistic DMZ $\rightarrow$ Internal $\rightarrow$ OT enclave architectures.
2. **Variable Sizing**: Subnets must contain a random number of containers. An internal enclave might have 50 flat machines, and only *one* of them acts as the bridge to the next isolated segment.

### The Logging Paradox Solved
Deeply nested, air-gapped machines present a logging challenge: if `decky-50` has no route to the internet or the logging network, how can it forward telemetry stealthily? 

**Solution**: DECNET completely bypasses the container networking stack by relying purely on Docker's native `stdout` and daemon-level logging drivers. Because the host daemon handles the extraction, the attacker can completely destroy the container's virtual interfaces or be 50 layers deep in an air-gap without ever noticing a magic route, and the telemetry will still perfectly reach the SIEM out-of-band.

### Simulated Topographical Latency
If an attacker proxies 5 subnets deep into what is supposed to be a secure, physically segmented enclave, and `ping` returns a flat `0.05ms` response time, they will instantly realize it's a local simulation on a single host.

To maintain the illusion of depth, DECNET can utilize the **Linux Traffic Control (`tc`)** subsystem and its **Network Emulator (`netem`)** module on the virtual bridge interfaces (`veth` pairs). 

By procedurally generating `tc` rules as the network scales, we can inject mathematical latency penalties per hop:
```bash
# Example: Add 45ms latency, +/- 10ms jitter on a normal curve, with 0.1% packet loss
tc qdisc add dev eth1 root netem delay 45ms 10ms distribution normal loss 0.1%
```
As an attacker pivots deeper into the "Spider Network," this injected latency compounds automatically. A proxy chain going 4 levels deep would realistically suffer from 150ms+ of latency and erratic jitter, perfectly mimicking the experience of routing over slow, multi-site corporate VPNs.

---

## Distributed Scale: Swarm Overlay Architecture

To scale DECNET across multiple physical racks or sites, DECNET can leverage **Docker Swarm Overlay Networks** to create a unified L2/L3 backbone without surrendering control to Swarm's "Orchestration" scheduler. 

### The `--attachable` Paradigm
By default, Docker's `overlay` driver requires Swarm mode but tightly couples it to `docker service` (which abstracts and randomizes container placement to balance loads). In honeypot deployments, absolute control over physical placement is critical (e.g., placing the `scada-archetype` explicitly on bare-metal node C in the DMZ).

To solve this, DECNET will initialize the swarm control plane simply to construct the backend VXLAN, but completely ignore the service scheduler in favor of `--attachable` networks:

1. **Initialize the Control Plane** (manager node + remote worker joins):
   ```bash
   docker swarm init
   ```
2. **Create the Attachable Backbone**:
   ```bash
   docker network create -d overlay --attachable decnet-backbone
   ```
3. **Deploy Standalone**: Keep relying entirely on local `decnet deploy` scripts on the individual physical nodes. Because the network is `attachable`, standalone container instances can seamlessly attach to it and communicate with containers running on completely different hardware across the globe as if they were on a local layer 2 switch!
