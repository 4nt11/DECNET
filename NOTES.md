# Initial steps

# Architecture

## DECNET-UNIHOST model

The unihost model is a mode in which DECNET deploys an _n_ amount of machines from a single one. This execution model lives in a decoy network which is accessible to an attacker from the outside.

Each decky (the son of the DECNET unihost) should have different services (RDP, SMB, SSH, FTP, etc) and all of them should communicate with an external, isolated network, which aggregates data and allows
visualizations to be made. Think of the ELK stack. That data is then passed back via Logstash or other methods to a SIEM device or something else that may be beneficiated by this collected data.

## DECNET-MULTIHOST (SWARM) model

The SWARM model is similar to the UNIHOST model, but the difference is that instead of one real machine, we have n>1 machines. Same thought process really, but deployment may be different.
A low cost option and fairly automatable one is the usage of Ansible, sshpass, or other tools.

# Modus operandi

## Docker-Compose

I will use Docker Compose extensively for this project. The reasons are:
- Easily managed.
- Easily extensible.
- Less overhead.

To be completely transparent: I asked Deepseek to write the initial `docker-compose.yml` file. It was mostly boilerplate, and most of it mainly modified or deleted. It doesn't exist anymore.

## Distro to use.

I will be using the `debian:bookworm-slim` image for all the containers. I might think about mixing in there some Ubuntu or a Centos, but for now, Debian will do just fine.

The distro I'm running is WSL Kali Linux. Let's hope this doesn't cause any problems down the road.

## Networking

It was a hussle, but I think MACVLAN or IPVLAN (thanks @Deepseek!) might work. The reasoning behind picking this networking driver is that for the project to work, it requires having containers the entire container accessible from the network. This is to attempt to masquarede them as real, live machines.

Now, we will need a publicly accesible, real server that has access to this "internal" network. I'll try MACVLAN first.

### MACVLAN Tests

I will first use the default network to see what happens.

```
docker network create -d macvlan \
  --subnet=192.168.1.0/24 \
  --gateway=192.168.1.1 \
  -o parent=eth0 localnet
```

#### Issues

This initial test doesn't seem to be working. Might be that I'm using WSL, so I downloaded a Ubuntu 22.04 Server ISO. I'll try the MACVLAN network on it. Now, if that doesn't work, I don't see how the 802.1q would work, at least on _my network_. Perhaps if I had a switch I could make it work, but currently I don't have one :c

---

