---
name: attacking-hardware-interfaces
description: Assess the physical attack surface of embedded devices — finding and using UART consoles, JTAG/SWD debug, and SPI/I2C flash; dumping firmware off-chip; triaging secure boot; and studying sub-GHz RF replay feasibility with an SDR. Use when you have physical access to a device or board, need to identify test pads and get a serial/root shell, want to read a flash chip with flashrom, or are evaluating a fixed- vs rolling-code radio in a shielded lab.
verified: 2026-08-07
---

# Attacking Hardware Interfaces

Physical access changes the game: the debug ports, flash chips, and boot process
the vendor assumed were private are all reachable. The work is finding the
interfaces on the board, using them to reach a shell or dump the firmware, and
judging whether the device's secure-boot and RF designs actually hold. Almost
everything here needs the device in hand and permission to open it.

## When to Use

- You have physical access to an embedded device or PCB and need to find its
  debug/serial/flash interfaces
- Getting a UART console or root shell, interrupting a bootloader, or halting the
  CPU over JTAG/SWD
- Dumping firmware off a SPI/I2C flash chip for analysis
- Triaging a secure-boot / chain-of-trust design for bypass feasibility
- Studying sub-GHz RF replay feasibility (fixed vs rolling code) in a lab

## When NOT to Use

- **Analyzing firmware you already dumped** — extraction, filesystem carving,
  binary analysis — is `analyzing-firmware-images`; this skill gets the bytes
  off the device and hands them there.
- **Wi-Fi attacks** — `attacking-wireless-networks`.
- **Bluetooth/BLE and NFC/RFID** specifically — `attacking-bluetooth-nfc`.
- **Reversing a specific binary** pulled from the device — `analyzing-binaries`.

## Find the Interfaces

Boards expose more than they should through unlabeled test pads and headers:

- **UART.** The most common win — a serial console, often a bootloader prompt or
  a root shell. Identify the four lines (TX, RX, GND, VCC) with a multimeter and
  a logic analyzer, then connect a **USB-TTL adapter** (FTDI/CP2102) and open the
  console with `screen`/`minicom`/`picocom`. Detect the baud rate (115200 is
  common) if it is not obvious.
- **JTAG / SWD.** Full debug access — halt the CPU, read/write memory and
  registers, dump firmware, patch. Identify the pinout (a **JTAGulator** brute-
  forces it) and drive it with **OpenOCD** and an adapter (Bus Pirate, J-Link,
  Black Magic Probe).
- **SPI / I2C flash.** The firmware lives on an external flash chip you can read
  directly — clip a **SOIC8** test clip on and dump with **flashrom** via a
  CH341A or Bus Pirate, in-circuit or after chip-off.
- **Logic analyzer** (Saleae, or sigrok/PulseView with cheap hardware) to
  identify and decode any of the above when the protocol or pinout is unknown.

## Turn an Interface Into Access

- **UART → shell.** Many devices drop straight to a root shell or an
  authenticated console. If not, **interrupt the bootloader** (U-Boot often takes
  a keypress) to change the kernel command line — booting into single-user mode
  or spawning a shell (`init=/bin/sh`) is a frequent, high-impact bypass.
- **JTAG → firmware and control.** Halt and dump flash/RAM, read secrets, or
  patch a check. JTAG left enabled on production is a full compromise of the
  device's software protections.
- **Flash dump → firmware.** A SPI dump *is* the firmware image; hand it to
  `analyzing-firmware-images` for extraction and analysis. This path works even
  when UART and JTAG are locked.

## Secure Boot and Fault Injection

Judge whether the chain of trust actually holds:

- **Chain of trust.** ROM verifies the bootloader, which verifies the kernel,
  and so on. The break is usually an unverified link — an unsigned stage, a debug
  path, or a check that can be skipped.
- **Fuses / lock bits.** Whether JTAG-disable and secure-boot fuses are actually
  blown on production units is a common oversight; an unblown fuse reopens the
  debug port.
- **Fault injection (glitching).** Voltage or clock glitches (ChipWhisperer-class
  tooling) can skip a signature check or a comparison at the exact instruction.
  This is advanced and often the only route past a correctly-implemented secure
  boot; scope it as a feasibility study, not a guaranteed result.

## RF Replay Feasibility (SDR)

For sub-GHz radios (remotes, sensors, alarms on ISM bands like 315/433/868/915
MHz):

- **Receive and analyze** with an **RTL-SDR** (receive-only) and **Universal
  Radio Hacker** or GNU Radio — capture the signal, recover the modulation and
  encoding.
- **The security question is fixed vs rolling code.** A fixed code replays
  trivially; a rolling code (KeeLoq-style) changes every press and resists naive
  replay. Determine which the target uses — that is the finding.
- **Transmitting** (with a HackRF or similar) is where the law lives: you may
  only transmit in a **shielded enclosure / RF-isolated lab**, never over the air
  on bands you are not licensed for. Frame active RF work as a lab feasibility
  study, because you cannot confine a real transmission to the target.

## Scope and Authorization

This skill assumes a device you own or are explicitly authorized to open and
modify — opening hardware is destructive-adjacent and voids assumptions the owner
may care about, so get that in scope in writing. Two hard edges:

- **RF transmission is regulated.** Receiving is generally passive; transmitting
  on licensed or safety-critical bands is a legal matter and a safety one. Keep
  active RF in a shielded lab, and treat spectrum law as a constraint you do not
  argue with.
- **Physical modification can brick the device.** Chip-off, glitching, and
  bootloader changes can be irreversible. Confirm the owner accepts that risk on
  the specific unit before you start.

## Rationalizations to Reject

- **"No labeled debug header, so there's no debug access."** UART and JTAG live
  on unlabeled test pads constantly. Probe with a multimeter and logic analyzer
  before concluding the interface is absent.
- **"The flash is encrypted / locked, so I can't get firmware."** Try the other
  paths — a UART bootloader, an enabled JTAG, or an unblown fuse often bypasses a
  locked flash entirely.
- **"Secure boot is enabled, so the chain is sound."** Enabled is not the same as
  complete. Check every link for an unsigned stage, a debug path, or an unblown
  fuse — and glitching may skip the check outright.
- **"I'll just transmit to test the remote."** Over-the-air transmission is
  regulated and can affect safety systems. Do active RF in a shielded lab, or
  keep the assessment to receive-and-analyze.
- **"A rolling code means replay is impossible, done."** Confirm it is genuinely
  rolling and correctly implemented; naming fixed vs rolling code *is* the
  deliverable, and weak rolling-code schemes have their own flaws.

## References

- `analyzing-firmware-images` — analyzing firmware once dumped off the device
- `attacking-bluetooth-nfc` — BLE and NFC/RFID RF surfaces
- `attacking-wireless-networks` — Wi-Fi
- `analyzing-binaries` — reversing a specific binary recovered from the device
- `maintaining-engagement-state` — recording physical access and irreversible changes
