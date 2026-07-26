---
name: testing-ics-ot-protocols
description: Test Industrial Control Systems and Operational Technology protocols — Modbus, DNP3, OPC UA, BACnet, EtherNet/IP, S7comm, MQTT — with safety-first methodology for SCADA and ICS environments. Use when assessing OT network security, testing ICS protocol authentication, reviewing IT-OT segmentation, or performing authorized ICS penetration testing.
---

# Testing ICS/OT Protocols

ICS/OT protocols were designed for reliability in isolated networks, not security on connected ones. Most have no authentication, no encryption, and no integrity checking. The danger is not that they are hard to exploit — it is that exploitation can have physical consequences, which is why safety constraints govern everything you do here.

## When to Use

- Assessing SCADA networks or ICS environments during an authorized engagement
- Testing Modbus, DNP3, OPC UA, BACnet, EtherNet/IP, S7comm, or MQTT devices in scope
- Performing an ICS-specific penetration test with OT safety requirements
- Reviewing OT network segmentation and Purdue model compliance
- Evaluating remote access pathways into control system networks
- Inventorying ICS assets and identifying unauthenticated protocol exposure

## When NOT to Use

- **Standard IT network scanning** — use `enumerating-network-services`
- **HMI web interfaces tested as regular web apps** — use `testing-web-applications`
- **Writing ICS-specific detection rules** — use `engineering-detections`

## Safety-First Principles

OT pentesting is not IT pentesting with different ports. The rules of engagement are fundamentally different because the targets control physical processes.

**Why active scanning is dangerous in OT:**

- PLCs and RTUs run minimal embedded firmware. A malformed packet or unexpected connection can crash the device, halt a process, or cause it to fail to a dangerous state.
- Restarting a PLC may require physical access, and the process it controls may not tolerate interruption.
- Some devices interpret any TCP connection as a command session — connecting is acting.
- Nmap's default service probes have crashed PLCs in production environments.

**Mandatory constraints:**

1. Always have an OT engineer or plant operator present or on immediate call during active testing.
2. Obtain written authorization that explicitly covers ICS/OT assets — general network pentest scope does not imply OT scope.
3. Test in maintenance windows whenever possible. Never test safety-instrumented systems (SIS) without explicit, separate authorization.
4. Start with passive observation. Move to active enumeration only after the passive phase confirms device types and the OT engineer approves.
5. Distinguish read-only operations (reading registers, querying device info) from write operations (setting coils, writing registers, issuing commands). Write operations require per-device approval.
6. Have a rollback plan for every write operation. Know the expected state before you change anything.
7. Document every interaction with every device, including timestamps and the exact commands sent.

## Protocol Overview

| Protocol | Default Port | Auth by Design | Encryption | Notes |
|---|---|---|---|---|
| Modbus TCP | 502 | No | No | Most common ICS protocol; any host on the network can read/write |
| DNP3 | 20000 | Optional (SA) | No | SCADA polling; Secure Authentication is rarely deployed |
| EtherNet/IP (CIP) | 44818 | No | No | Rockwell/Allen-Bradley ecosystem |
| OPC UA | 4840 | Yes (multiple modes) | Optional (TLS) | Modern; security depends entirely on configuration |
| BACnet/IP | 47808 (UDP) | No | No | Building automation — HVAC, lighting, access control |
| S7comm | 102 | No | No | Siemens S7 PLCs; replaced by S7comm-plus with some protection |
| MQTT | 1883 / 8883 (TLS) | Optional | Optional (TLS) | IoT/ICS messaging; brokers often left open |

## Passive Reconnaissance

Start here. Passive observation carries no risk of disrupting devices and provides the asset inventory you need before touching anything.

**Wireshark with ICS dissectors:**
```bash
# Capture on the OT network interface (mirror/span port or tap)
tcpdump -i eth0 -w ics_capture.pcap -n

# Wireshark filters for ICS protocols
# Modbus
modbus

# DNP3
dnp3

# EtherNet/IP
enip

# OPC UA
opcua

# BACnet
bacnet

# S7comm
s7comm

# MQTT
mqtt
```

**What to extract from passive captures:**

- Device IP addresses and MAC addresses (OUI lookup identifies vendor — Siemens, Rockwell, Schneider, ABB)
- Protocol distribution — which protocols are in use, on which segments
- Polling patterns — master/slave relationships, polling intervals, which registers are read
- Firmware versions visible in protocol banners or response fields
- Unexpected traffic — IT protocols on OT segments, devices communicating outside expected patterns
- Unencrypted credentials in MQTT CONNECT packets, OPC UA sessions, or HTTP-based HMIs

**Asset inventory from passive observation:**

Build a table: IP, MAC, vendor (from OUI), protocol(s) observed, role (master/slave/HMI/historian), firmware version if visible. This becomes the basis for active enumeration scope.

## Active Enumeration (When Authorized)

Only proceed after: (1) passive recon is complete, (2) OT engineer has reviewed the asset list and approved active testing, (3) scope explicitly includes active ICS enumeration.

**Safe nmap usage for ICS:**
```bash
# NEVER use aggressive timing or default scripts against OT devices
# Use slow timing and specific ICS scripts only

# Modbus device discovery
nmap -Pn -sT -p 502 --script modbus-discover TARGET

# Siemens S7 device info (read-only query)
nmap -Pn -sT -p 102 --script s7-info TARGET

# BACnet device enumeration
nmap -Pn -sU -p 47808 --script bacnet-info TARGET

# EtherNet/IP enumeration
nmap -Pn -sT -p 44818 --script enip-info TARGET

# OPC UA discovery
nmap -Pn -sT -p 4840 --script opcua-endpoints TARGET

# IMPORTANT: Use -Pn (skip host discovery), -sT (full connect, not SYN scan),
# and NEVER use -A, -sV with high intensity, or broad script categories
# against OT devices.
```

**Dedicated ICS scanning tools:**
```bash
# plcscan — lightweight PLC scanner
plcscan -t TARGET

# Redpoint Nmap scripts (Digital Bond)
# These are ICS-specific and safer than generic nmap scripts
nmap --script redpoint/ -p 502,44818,47808,102,20000 TARGET
```

## Protocol-Specific Testing

### Modbus TCP (Port 502)

Modbus has no authentication. Any host that can reach port 502 can read sensors, write to coils, and control the PLC. This is by design — it was created in 1979 for serial links in isolated environments.

**Reading coils and registers (read-only, lower risk):**
```bash
# Using modbus-cli
modbus read TARGET 0 10          # Read 10 holding registers starting at address 0
modbus read -s coil TARGET 0 10  # Read 10 coils starting at address 0

# Using mbtget
mbtget -a 1 -r1 -n 10 TARGET    # Read 10 holding registers, unit ID 1
mbtget -a 1 -r2 -n 10 TARGET    # Read 10 input registers

# Python with pymodbus
python3 -c "
from pymodbus.client import ModbusTcpClient
client = ModbusTcpClient('TARGET')
client.connect()
result = client.read_holding_registers(0, 10, unit=1)
print(result.registers)
client.close()
"
```

**Key Modbus function codes:**
```
FC 01 - Read Coils (digital outputs)
FC 02 - Read Discrete Inputs (digital inputs)
FC 03 - Read Holding Registers (analog outputs / config)
FC 04 - Read Input Registers (analog inputs)
FC 05 - Write Single Coil              ← WRITE — requires explicit approval
FC 06 - Write Single Register           ← WRITE — requires explicit approval
FC 15 - Write Multiple Coils            ← WRITE — requires explicit approval
FC 16 - Write Multiple Registers        ← WRITE — requires explicit approval
FC 43 - Read Device Identification
```

**The finding to report:** If you can reach port 502 from outside the process control network, the control system has no access control. This is almost always Critical — document the network path and what registers you could read.

### OPC UA (Port 4840)

OPC UA is the one ICS protocol that was designed with security in mind. Whether it is actually secure depends on how it is configured.

**Discovery and endpoint enumeration:**
```bash
# List OPC UA endpoints and their security modes
# Using opcua-client-gui or UaExpert

# Python with opcua library
python3 -c "
from opcua import Client
client = Client('opc.tcp://TARGET:4840')
endpoints = client.connect_and_get_server_endpoints()
for ep in endpoints:
    print(f'Endpoint: {ep.EndpointUrl}')
    print(f'  Security Mode: {ep.SecurityMode}')
    print(f'  Security Policy: {ep.SecurityPolicyUri}')
    print(f'  User Token: {[t.TokenType for t in ep.UserIdentityTokens]}')
"
```

**Authentication modes to check:**
- **Anonymous** — no credentials required. If this endpoint exists and is reachable, report it.
- **Username/Password** — test for defaults (admin/admin, user/password, opcua/opcua).
- **Certificate** — strongest mode. Verify certificates are validated, not just accepted.

**Common OPC UA findings:**
- Anonymous authentication enabled alongside authenticated endpoints
- Security Mode set to None (no signing or encryption)
- Self-signed certificates accepted without validation
- Default credentials on Username/Password endpoints

### DNP3 (Port 20000)

```bash
# DNP3 enumeration — identify master/outstation roles
nmap -Pn -sT -p 20000 --script dnp3-info TARGET

# Check for DNP3 Secure Authentication (rarely deployed)
# Most DNP3 implementations have no authentication at all
```

### BACnet (Port 47808 UDP)

```bash
# BACnet device discovery
nmap -Pn -sU -p 47808 --script bacnet-info TARGET

# BACnet enumeration with BAC0
python3 -c "
import BAC0
bacnet = BAC0.lite(ip='YOUR_IP/24')
devices = bacnet.whois()
print(devices)
"
```

### S7comm (Port 102)

```bash
# Siemens S7 PLC information
nmap -Pn -sT -p 102 --script s7-info TARGET

# Identifies: module name, serial number, plant identification,
# firmware version, hardware version, CPU state
```

## Common Findings

These appear in the majority of ICS assessments:

**1. Flat networks (IT-OT convergence)**
The single most impactful finding. No segmentation between corporate IT and control systems means any compromised workstation can reach PLCs directly. Test by attempting to reach ICS ports from IT network segments.

**2. Default credentials on HMIs and engineering workstations**
HMI web interfaces, VNC servers on operator stations, and engineering software often use factory defaults. Check vendor documentation for default credentials before testing.

**3. Unauthenticated protocols exposed to non-process networks**
Modbus, S7comm, and BACnet have no authentication. If these ports are reachable from outside the process control network, any compromised host can control physical processes.

**4. Unencrypted protocols carrying sensitive data**
Credentials, process values, and configuration data transmitted in cleartext. Demonstrate with a packet capture showing readable data.

**5. Remote access gateways with weak controls**
VPN concentrators, jump hosts, or cellular modems providing remote access to OT networks. Check for multi-factor authentication, session logging, and access restrictions.

**6. Outdated firmware with known vulnerabilities**
ICS devices often run firmware years behind current releases because patching requires downtime. Document versions and map to known CVEs, but do not attempt exploitation without explicit approval.

**7. Historian and data diode misconfigurations**
Historians bridging IT and OT should be in a DMZ. Data diodes should enforce unidirectional flow. Verify with traffic analysis.

## Network Segmentation Review

Assess against the Purdue Enterprise Reference Architecture:

```
Level 5  Enterprise network (corporate IT)
Level 4  Site business planning (ERP, email)
         ─── IT/OT DMZ ───
Level 3  Site operations (historians, OPC servers)
Level 2  Area supervisory control (HMI, engineering workstations)
Level 1  Basic control (PLCs, RTUs, controllers)
Level 0  Process (sensors, actuators, field devices)
```

**What to verify:**

- Is there a DMZ between Level 3 and Level 4? Traffic should not flow directly between IT and OT.
- Are data diodes or unidirectional gateways in place where required?
- Can Level 5/4 hosts reach Level 1/0 devices? (They should not.)
- Are jump hosts or bastion hosts required for remote access to OT?
- Is east-west traffic within OT segmented (Level 2 from Level 1, separate process zones)?
- Are firewall rules default-deny with explicit allows, or default-allow?

## Defensive Review Checklist

When reviewing ICS security posture rather than attacking:

- [ ] Asset inventory exists and is current (know every device on the OT network)
- [ ] Network segmentation follows Purdue model or equivalent zoning
- [ ] IT-OT DMZ is implemented with firewalls and monitoring
- [ ] Remote access requires MFA and lands in a jump host, not directly on OT
- [ ] ICS protocol traffic is monitored (Claroty, Dragos, Nozomi, or equivalent)
- [ ] Patch management process exists for OT assets (even if patching is infrequent)
- [ ] Default credentials have been changed on all HMIs, switches, and engineering software
- [ ] USB and portable media policies are enforced in OT environments
- [ ] Backup and recovery procedures exist for PLC programs and configurations
- [ ] Incident response plan includes OT-specific scenarios (not just IT playbooks)
- [ ] Safety-instrumented systems (SIS) are on isolated networks, not reachable from process control

## Rationalizations to Reject

- *"We can just scan it like a normal network."* You cannot. A SYN scan can
  crash a PLC and stop a physical process. OT scanning requires device-specific
  knowledge, slow timing, and an engineer who can intervene.
- *"It is air-gapped, so we do not need to test it."* Air gaps rarely survive
  contact with reality. USB drives, maintenance laptops, cellular modems, and
  vendor VPNs create paths that bypass the gap.
- *"The OT team says we cannot touch anything."* Then scope passive assessment
  only — traffic capture and architecture review still produce high-value
  findings. Do not skip the engagement.
- *"We found Modbus open, that is enough."* Document the network path, what
  registers you could read, and what they control. "Port 502 open" is a scan
  result, not a finding.
- *"We do not need the OT engineer present for read-only testing."* Read
  operations on some devices have side effects. The engineer knows which devices
  are sensitive. Keep them in the loop.
- *"Let us write a coil to prove impact."* Writing to a PLC in a production
  environment can cause physical damage. Demonstrate the ability to write
  without actually writing, or test in a maintenance window with the process
  safely shut down.
- *"The vendor says the protocol is secure."* Vendor claims about proprietary
  protocol security are not evidence. Test it. Many "proprietary" protocols are
  trivially reverse-engineered or provide security through obscurity only.

## References

- `enumerating-network-services` — standard IT network service enumeration
- `engineering-detections` — writing detection rules for ICS-specific threats
- `reporting-security-findings` — structuring ICS findings for maximum impact
- IEC 62443 (industrial automation security); NIST SP 800-82 (guide to ICS security)
- MITRE ATT&CK for ICS: https://attack.mitre.org/techniques/ics/
