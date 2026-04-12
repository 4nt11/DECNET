# ICS/SCADA Bait — Plan

> Scenario: attacker finds MQTT broker on a water treatment plant, subscribes to
> sensor topics, publishes commands trying to "open the valve" or "disable chlorination".

---

## Services in scope

| Service | Port | Current state | Target state |
|---------|------|--------------|-------------|
| MQTT | 1883 | CONNACK 0x05 (reject all) | CONNACK 0x00, fake sensor topics |
| SNMP | 161/UDP | Functional, generic sysDescr | sysDescr tuned per archetype |
| Conpot | 502 | Not responding | Investigate + fix port mapping |

---

## MQTT — water plant persona

### Current behavior

Every CONNECT gets `CONNACK 0x05` (Not Authorized) and the connection is closed.
An ICS attacker immediately moves on — there's nothing to interact with.

### Target behavior

Accept all connections (`CONNACK 0x00`). Publish retained sensor data on
realistic SCADA topics. Log every PUBLISH command (attacker trying to control plant).

### Topic tree

```
plant/water/tank1/level         → "73.4" (percent full)
plant/water/tank1/pressure      → "2.81" (bar)
plant/water/pump1/status        → "RUNNING"
plant/water/pump1/rpm           → "1420"
plant/water/pump2/status        → "STANDBY"
plant/water/chlorine/dosing     → "1.2" (mg/L)
plant/water/chlorine/residual   → "0.8" (mg/L)
plant/water/valve/inlet/state   → "OPEN"
plant/water/valve/drain/state   → "CLOSED"
plant/alarm/high_pressure       → "0"
plant/alarm/low_chlorine        → "0"
plant/alarm/pump_fault          → "0"
plant/$SYS/broker/version       → "Mosquitto 2.0.15"
plant/$SYS/broker/uptime        → "2847392 seconds"
```

All topics have `retain=True` so subscribers immediately receive the last value.

### Protocol changes needed

Add handling for:

- **SUBSCRIBE (pkt_type=8)**: Parse topic filter + QoS pairs. For each matching topic,
  send SUBACK then immediately send a PUBLISH with the retained value.
- **PUBLISH (pkt_type=3)**: Log the topic + payload (this is the attacker "sending a command").
  Return PUBACK for QoS 1. Do NOT update the retained value (the plant ignores the command).
- **PINGREQ (pkt_type=12)**: Already handled. Keep alive.
- **DISCONNECT (pkt_type=14)**: Close cleanly.

Do NOT implement: UNSUBSCRIBE, QoS 2. Return SUBACK with QoS 1 for all subscriptions.

### CONNACK change

```python
_CONNACK_ACCEPTED = b"\x20\x02\x00\x00"   # session_present=0, return_code=0
```

### Env vars

| Var | Default | Description |
|-----|---------|-------------|
| `MQTT_PERSONA` | `water_plant` | Topic tree preset |
| `MQTT_ACCEPT_ALL` | `1` | Accept all connections |
| `NODE_NAME` | `mqtt-broker` | Hostname in logs |

---

## SUBSCRIBE packet parsing

```python
def _parse_subscribe(payload: bytes):
    """Returns (packet_id, [(topic, qos), ...])"""
    pos = 0
    packet_id = struct.unpack(">H", payload[pos:pos+2])[0]
    pos += 2
    topics = []
    while pos < len(payload):
        topic, pos = _read_utf8(payload, pos)
        qos = payload[pos] & 0x03
        pos += 1
        topics.append((topic, qos))
    return packet_id, topics
```

### SUBACK

```python
def _suback(packet_id: int, granted_qos: list[int]) -> bytes:
    payload = struct.pack(">H", packet_id) + bytes(granted_qos)
    return bytes([0x90, len(payload)]) + payload
```

### PUBLISH (server → client, retained)

```python
def _publish(topic: str, value: str, retain: bool = True) -> bytes:
    topic_bytes = topic.encode()
    topic_len   = struct.pack(">H", len(topic_bytes))
    payload     = value.encode()
    # Fixed header: type=3, retain flag, no QoS (fire and forget for retained)
    fixed = 0x31 if retain else 0x30
    remaining = len(topic_len) + len(topic_bytes) + len(payload)
    return bytes([fixed, remaining]) + topic_len + topic_bytes + payload
```

---

## SNMP — sysDescr per archetype

Current `sysDescr` is a generic Linux string. It should reflect the decky's persona.

### Archetype strings

| Archetype | sysDescr |
|-----------|---------|
| water_plant | `Linux scada-plc01 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64` |
| factory | `VxWorks 6.9 (Rockwell Automation Allen-Bradley ControlLogix 5580)` |
| substation | `SEL Real-Time Automation Controller RTAC SEL-3555 firmware 1.9.7.0` |
| hospital | `Linux medlogic-srv01 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 x86_64` |
| default | `Linux decky-host 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64` |

Env var `SNMP_ARCHETYPE` selects the string. The SNMP server should also tune:

- `sysContact.0` → `ICS Admin <ics-admin@plant.local>`
- `sysLocation.0` → `Water Treatment Facility — Pump Room B`
- `sysName.0` → `scada-plc01` (from `NODE_NAME`)

---

## Conpot — Modbus TCP (port 502)

### Current state

Port 502 shows `CLOSED` in nmap. Conpot is deployed as a service container but
is either not binding to 502 or the port mapping is wrong.

### Diagnosis steps

1. Check the compose fragment: `decnet services conpot` — what port does it expose?
2. `docker exec decky-01-conpot netstat -tlnp` or `ss -tlnp` — is Conpot listening on 502?
3. Check Conpot's default config — it may listen on a non-standard port (e.g. 5020) and
   expect a host-level iptables REDIRECT rule to map 502 → 5020.

### Fix options

**Option A** (preferred): Configure Conpot to listen directly on 502 by editing its
`default.xml` template and setting `<port>502</port>`.

**Option B**: Add `iptables -t nat -A PREROUTING -p tcp --dport 502 -j REDIRECT --to-port 5020`
to the base container entrypoint. Fragile — prefer A.

### What Modbus should respond

Conpot's default Modbus template already implements a plausible PLC. The key registers
to tune for water-plant persona:

| Register | Address | Value | Description |
|----------|---------|-------|-------------|
| Coil | 0 | 1 | Pump 1 running |
| Coil | 1 | 0 | Pump 2 standby |
| Holding | 0 | 734 | Tank level (73.4%) |
| Holding | 1 | 281 | Pressure (2.81 bar × 100) |
| Holding | 2 | 12  | Chlorine dosing (1.2 mg/L × 10) |

These values should be consistent with the MQTT topic tree so an attacker who
probes both sees a coherent picture.

---

## Log events

### MQTT

| event_type | Fields | Trigger |
|------------|--------|---------|
| `connect` | src, src_port, client_id, username | CONNECT packet |
| `subscribe` | src, topics | SUBSCRIBE packet |
| `publish` | src, topic, payload | PUBLISH from client (attacker command!) |
| `disconnect` | src | DISCONNECT or connection lost |

### SNMP

No changes to event structure — sysDescr is just a config string.

---

## Files to change

| File | Change |
|------|--------|
| `templates/mqtt/server.py` | Accept connections, SUBSCRIBE handler, retained PUBLISH, PUBLISH log |
| `templates/snmp/server.py` | Add `SNMP_ARCHETYPE` env var, tune sysDescr/sysContact/sysLocation |
| `templates/conpot/` | Investigate port config, fix 502 binding |
| `tests/test_mqtt.py` | New: connect accepted, subscribe → retained publish, attacker publish logged |
| `tests/test_snmp.py` | Extend: sysDescr per archetype |

---

## Verification against live decky

```bash
# MQTT: connect and subscribe
mosquitto_sub -h 192.168.1.200 -t "plant/#" -v

# Expected output:
# plant/water/tank1/level 73.4
# plant/water/pump1/status RUNNING
# ...

# MQTT: attacker sends a command (should be logged)
mosquitto_pub -h 192.168.1.200 -t "plant/water/valve/inlet/state" -m "CLOSED"

# Modbus: read coil 0 (pump status)
# (requires mbpoll or similar)
mbpoll -a 1 -r 1 -c 2 192.168.1.200

# SNMP: sysDescr check
snmpget -v2c -c public 192.168.1.200 1.3.6.1.2.1.1.1.0
# Expected: STRING: "Linux scada-plc01 4.19.0..."
```
