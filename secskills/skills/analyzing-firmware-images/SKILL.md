---
name: analyzing-firmware-images
description: Extract, analyze, and assess firmware images from embedded devices, IoT hardware, routers, and similar targets — filesystem extraction, hardcoded credential discovery, binary analysis across architectures, web interface review, network service enumeration, emulation, and cryptographic assessment. Use when analyzing a firmware update file, reviewing IoT device security, hunting for hardcoded secrets in device firmware, or assessing the attack surface of an embedded system.
---

# Analyzing Firmware Images

Firmware is a frozen Linux (or RTOS) image, and its security froze with it.
Hardcoded credentials, command injection in CGI scripts, unsigned update
packages, and debug interfaces left enabled are not edge cases -- they are
the baseline. The work is extraction, orientation, and then asking the same
questions you would ask of any system, with the knowledge that nobody has
patched this one since it shipped.

## When to Use

- Extracting and analyzing a firmware update file (.bin, .img, .chk, .trx)
- Reviewing IoT device security posture from a firmware image
- Looking for hardcoded credentials, keys, or secrets in device firmware
- Assessing the attack surface of an embedded device or router
- Evaluating update mechanisms and signature verification
- Analyzing a bare-metal or RTOS image from a microcontroller

## When NOT to Use

- **Standard x86/x64 binary reverse engineering** -- use `analyzing-binaries`
- **Malware sample analysis** -- use `analyzing-malware`
- **Source code is available** -- use `auditing-code-for-vulnerabilities`

## Firmware Acquisition

Before analysis comes acquisition. The method determines what you get.

| Method | What you get | Notes |
| --- | --- | --- |
| Vendor download | Update package, often compressed or encrypted | Check support portals, FTP servers, and FCC filings |
| OTA sniffing | Update payload in transit | mitmproxy or tcpdump on the device's update channel; many devices use plain HTTP |
| UART/serial console | Shell access, bootloader interaction | Three wires (TX, RX, GND); identify with a multimeter or logic analyzer |
| JTAG/SWD | Full memory read, debug access | Requires pin identification; JTAGulator, OpenOCD |
| Chip-off | Raw flash contents (NAND/NOR) | Desolder the flash chip; read with a programmer (CH341A, FlashcatUSB); last resort |
| Bootloader extraction | Dump via U-Boot `md` or `sf read` commands | If the bootloader shell is accessible over UART |

For OTA interception, configure the device to proxy through mitmproxy. Many
devices ignore proxy settings -- ARP spoofing or a transparent bridge may be
required. If the update is over HTTPS, check whether the device validates
certificates at all; a surprising number do not.

## Initial Analysis

Start with format identification and entropy analysis before extracting.

```bash
file firmware.bin
binwalk firmware.bin              # identify embedded filesystems and compression
binwalk -E firmware.bin           # entropy analysis -- high entropy = compressed or encrypted
hexdump -C firmware.bin | head -64   # header bytes reveal container format
strings -n 10 firmware.bin | head -100  # quick orientation
```

**What the entropy plot tells you:**

- **Flat high entropy (close to 1.0) across the entire image** -- encrypted
  or compressed as a unit. You need the decryption key or decompression
  method before you can proceed.
- **Regions of high entropy separated by low-entropy headers** -- compressed
  filesystem partitions with metadata between them. Normal; extract the
  partitions.
- **Low entropy throughout** -- uncompressed filesystem or raw flash. Direct
  extraction should work.

Common container formats:

| Header magic | Format |
| --- | --- |
| `hsqs` / `sqsh` | SquashFS |
| `UBI#` | UBI/UBIFS |
| `0x1985` | JFFS2 |
| `0x28cd3d45` | cramfs |
| `HDR0` | TRX (Broadcom routers) |
| `\x27\x05\x19\x56` | uImage (U-Boot) |

## Extraction

Use the right tool for the filesystem. Generic extraction misses metadata
and permissions.

```bash
# General recursive extraction -- good starting point
binwalk -Me firmware.bin

# SquashFS -- the most common embedded filesystem
unsquashfs -d rootfs squashfs-root.img
# Non-standard SquashFS (vendor-modified): use sasquatch
sasquatch -d rootfs squashfs-root.img

# JFFS2
jefferson firmware.jffs2 -d rootfs

# UBI/UBIFS
ubireader_extract_images firmware.ubi
ubireader_extract_files firmware.ubi

# cramfs
cramfsck -x rootfs cramfs.img

# Raw NAND dumps may need OOB data stripped first
nandextract firmware.nand
```

If binwalk finds nothing and entropy is high, the image is likely encrypted.
Look for a bootloader or earlier firmware version that contains the
decryption routine. Some vendors ship the decryption key in the bootloader
or in a companion partition.

## Filesystem Analysis

Once extracted, treat the rootfs as a Linux system you are auditing for the
first time.

### Credentials and Secrets

```bash
# Password files
cat rootfs/etc/passwd
cat rootfs/etc/shadow
# Hardcoded credentials -- these are endemic
rg -rn 'password|passwd|admin|root|default' rootfs/etc/ --include='*.conf'
rg -rn 'BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY' rootfs/
rg -rn 'api[_-]?key|secret[_-]?key|token' -i rootfs/

# Certificates and keys
find rootfs -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.p12'
# WiFi and VPN credentials
find rootfs -name 'wpa_supplicant*' -o -name '*.ovpn' -o -name 'ipsec.*'
```

Default credentials in `/etc/shadow` are the single most common firmware
finding. Check whether root has a password hash and whether it is crackable
-- it usually is. See `cracking-passwords` for hash handling.

### Configuration and Services

```bash
# Startup scripts reveal what runs and how
ls rootfs/etc/init.d/ rootfs/etc/rc.d/
cat rootfs/etc/inittab
# Systemd units if present
find rootfs -name '*.service' -path '*/systemd/*'

# Installed packages and versions
cat rootfs/etc/opkg/status 2>/dev/null    # OpenWrt-based
ls rootfs/usr/lib/ipkg/info/ 2>/dev/null  # older ipkg

# Network configuration
cat rootfs/etc/network/interfaces 2>/dev/null
rg -rn 'iptables|ip6tables|nftables' rootfs/etc/
```

### Web Interface

The web interface is where the exploitable bugs live. Embedded web servers
are typically BusyBox httpd, lighttpd, uhttpd, or GoAhead, serving CGI
scripts written in shell, Lua, or C.

```bash
# Find the web root
find rootfs -name 'httpd*' -o -name 'lighttpd*' -o -name 'uhttpd*'
ls rootfs/www/ rootfs/usr/www/ rootfs/usr/share/www/ 2>/dev/null

# CGI scripts -- these are the attack surface
find rootfs -name '*.cgi' -o -name '*.sh' -path '*/cgi-bin/*'
find rootfs -name '*.lua' -path '*/luci/*' -o -name '*.lua' -path '*/www/*'

# Command injection patterns in CGI
rg -rn 'system\(|popen\(|exec\(|os\.execute|io\.popen|\`.*\$' rootfs/www/
rg -rn '\$QUERY_STRING|\$REQUEST_URI|\$HTTP_' rootfs/www/
```

**Command injection through CGI parameters is endemic in embedded web
interfaces.** The pattern is a CGI script that takes user input from a query
parameter and passes it to a shell command without sanitization. Review
every CGI script for this pattern -- `system()`, `popen()`, backtick
execution, `os.execute()`, and `io.popen()` with any user-controlled input.

Also check for:
- Authentication bypass (pages accessible without login)
- Cross-site scripting in diagnostic pages (ping, traceroute, DNS lookup)
- Path traversal in file-serving handlers
- Hardcoded session tokens or predictable session generation

## Binary Analysis

Firmware binaries target non-x86 architectures. Identify the architecture
before disassembly.

```bash
# Identify architecture from ELF headers
file rootfs/usr/sbin/*
readelf -h rootfs/usr/sbin/httpd    # Machine field: ARM, MIPS, PowerPC

# Common architectures in firmware
# ARM (little-endian)  -- modern IoT, cameras, some routers
# MIPS (big-endian)    -- routers (Broadcom, Atheros, MediaTek)
# MIPS (little-endian) -- some Realtek-based devices
# PowerPC              -- older enterprise networking gear
```

### Cross-Architecture Disassembly

Ghidra handles all common firmware architectures natively. Load the binary,
select the correct processor and endianness, and auto-analyze.

```bash
# Ghidra headless analysis
analyzeHeadless /proj FirmwareProj -import rootfs/usr/sbin/httpd \
  -processor ARM:LE:32:v7 -postScript DecompileAll.java

# radare2 with architecture specification
r2 -a arm -b 32 rootfs/usr/sbin/httpd
# For MIPS big-endian:
r2 -a mips -b 32 -e cfg.bigendian=true rootfs/usr/bin/target
```

Focus disassembly on:
- The web server and CGI handler binaries
- Custom daemons (anything not from BusyBox or standard packages)
- Shared libraries that implement device-specific functionality
- Binaries that run as root and accept network input

### Emulation with QEMU

```bash
# User-mode emulation for individual binaries
qemu-arm -L rootfs/ rootfs/usr/sbin/httpd
qemu-mipsel -L rootfs/ rootfs/usr/bin/target
# Use -strace to trace syscalls
qemu-arm -strace -L rootfs/ rootfs/usr/sbin/httpd

# If the binary needs specific /dev nodes or /proc, use chroot
sudo chroot rootfs/ /usr/sbin/httpd
# Or mount necessary filesystems
sudo mount -t proc proc rootfs/proc
sudo mount -t sysfs sysfs rootfs/sys
```

## Network Services

Enumerate what the device exposes on the network by reading init scripts
and binary configurations rather than by scanning a live device.

```bash
# Services started at boot
rg -rn 'start\(\)|start_service' rootfs/etc/init.d/
# Listening ports from configuration
rg -rn 'listen|bind|port' rootfs/etc/ --include='*.conf'

# Common embedded services to look for
find rootfs -name 'telnetd' -o -name 'dropbear' -o -name 'sshd'
find rootfs -name 'upnpd' -o -name 'miniupnpd' -o -name 'minissdpd'
find rootfs -name 'mosquitto*' -o -name 'mqtt*'
find rootfs -name 'snmpd' -o -name 'snmp.conf'
```

**Common findings:**
- Telnet enabled with default or no credentials
- UPnP/SSDP exposing internal service descriptions to the WAN
- MQTT brokers with no authentication
- SNMP with default community strings (`public`, `private`)
- Custom management protocols on non-standard ports with no authentication
- TR-069 (CWMP) interfaces exposed beyond the ISP management VLAN
- Debug ports (GDB server, serial-over-network) left active in production

## Full-System Emulation

When individual binary emulation is insufficient, emulate the entire
firmware.

```bash
# FirmAE -- automated full-system emulation
sudo python3 firmae.py -r <brand> firmware.bin

# EMBA -- comprehensive firmware analysis framework
sudo ./emba -f firmware.bin -l ./logs

# firmwalker -- static analysis without emulation
./firmwalker.sh rootfs/
```

FirmAE and EMBA handle the hard parts: inferring the correct QEMU machine
type, setting up the network, and patching `/dev/` nodes. If they fail,
manual QEMU system emulation requires building the correct device tree and
kernel for the target platform.

Once a full system is running, test it as you would any networked service:
scan with nmap, test the web interface, fuzz the custom protocols. The
difference is that you have the filesystem and can read the code while you
test.

## Cryptographic Analysis

Firmware images routinely contain cryptographic material and implement
custom cryptographic schemes.

```bash
# Find encryption keys and certificates
find rootfs -name '*.pem' -o -name '*.der' -o -name '*.key' -o -name '*.pub'
rg -rn 'AES|DES|RSA|SHA256|MD5|encrypt|decrypt' rootfs/usr/lib/ --include='*.so'

# Check update signature verification
# Look for signature checks in the update handler
rg -rn 'verify|signature|sign|openssl|gpg' rootfs/usr/sbin/ rootfs/etc/init.d/
```

**What to look for:**

- **Unsigned firmware updates** -- if the update mechanism does not verify a
  cryptographic signature, an attacker with network position can push
  arbitrary firmware. This is critical.
- **Symmetric-only update signing** -- a shared key embedded in the firmware
  itself means anyone with the firmware can sign updates. Extract the key
  and demonstrate.
- **Hardcoded TLS certificates and private keys** -- every device ships with
  the same key pair. Extract and demonstrate that one device's key decrypts
  another device's traffic.
- **Weak or custom encryption** -- XOR "encryption" of configuration files,
  hardcoded keys for "encrypting" passwords, custom obfuscation routines
  that are not encryption at all.
- **Entropy sources** -- embedded devices often have poor entropy at boot.
  Check whether `/dev/urandom` is seeded properly, whether the RNG is
  initialized before key generation, and whether the device has a hardware
  RNG that is actually used.

See `reviewing-cryptography` for detailed cryptographic review methodology.

## Defensive Review Checklist

After completing the analysis, evaluate against these controls. The absence
of any item is a finding.

| Control | Check | Common failure |
| --- | --- | --- |
| Signed updates | Is the update package cryptographically signed with an asymmetric key? Is the signature verified before flashing? | No signature at all, or symmetric-only |
| Secure boot | Does the bootloader verify the kernel and rootfs integrity? | U-Boot with no signature verification |
| No default credentials | Does the device force a password change on first use? | root:root, admin:admin, or blank passwords |
| Minimal services | Are only necessary services enabled? | Telnet, UPnP, SNMP enabled by default |
| Debug interfaces | Are UART, JTAG, and SSH disabled or locked in production? | UART shell with root access, no authentication |
| Encrypted storage | Are credentials and keys stored encrypted at rest? | Plaintext passwords in config files |
| TLS everywhere | Do all network services use TLS with valid certificates? | Plain HTTP for web management, plain MQTT |
| Input validation | Do CGI and API handlers validate and sanitize input? | Direct shell injection through web parameters |
| Least privilege | Do services run as non-root where possible? | Everything runs as root |
| Logging and audit | Are security events logged? | No logging, or logs only in volatile memory |

## Rationalizations to Reject

- *"It's on an isolated network."* Embedded devices get exposed -- through
  UPnP, through misconfigured firewalls, through the cloud management
  portal that phones home. Assume reachability.
- *"The firmware is encrypted, so we can't analyze it."* The decryption key
  is in the bootloader or in a previous unencrypted version. Encryption
  without secure boot is obfuscation, not protection.
- *"It's just a consumer device."* Consumer devices form botnets. The same
  vulnerability classes apply.
- *"We can't patch it, so why report it?"* Document it so the risk is
  understood and compensating controls can be applied.
- *"The vendor says it's secure."* Vendor attestation is not evidence. The
  filesystem is evidence.
- *"It's a custom RTOS, not Linux, so standard tools won't work."* The
  architecture-level tools (Ghidra, QEMU, binwalk entropy) work on any
  binary. Adapt the methodology, do not skip the analysis.
- *"Nobody would bother attacking this device."* Mirai scanned the entire
  IPv4 space for default credentials. The bar for "bother" is a single
  script.

## References

- `analyzing-binaries` -- disassembly and reverse engineering methodology
- `auditing-code-for-vulnerabilities` -- source-level review when code is available
- `enumerating-network-services` -- service discovery and assessment
- `reviewing-cryptography` -- cryptographic implementation review
