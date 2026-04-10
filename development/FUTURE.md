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
