---
name: analyzing-memory-images
description: Analyze volatile memory images (RAM dumps) using Volatility 3 — process enumeration, injected code detection, credential extraction, network artifacts, rootkit analysis, and timeline construction from memory-resident data. Use when examining a memory capture from a compromised host, hunting for injected code or hollowed processes, extracting credentials or network state from RAM, or detecting kernel-level rootkits.
---

# Analyzing Memory Images

Memory is the only place certain artifacts exist — injected code, decrypted
payloads, credential material, and network connections from processes that have
already exited. Disk forensics misses all of these. The work is getting the
image before it is lost, then asking the right questions in the right order.

## When to Use

- You have a memory dump (raw, LiME, EWF, crash dump, or VM snapshot) to analyze
- Investigating a compromised host and need artifacts that exist only in RAM
- Looking for injected code, process hollowing, or reflective DLL loading
- Extracting credential material — hashes, Kerberos tickets, cached credentials
- Identifying network connections and listening ports from a point-in-time capture
- Detecting kernel-level rootkits — SSDT hooks, DKOM, hidden drivers

## When NOT to Use

- **Broader incident response methodology** — use `responding-to-incidents`
- **You have an acquired disk image, not a RAM capture** — use `analyzing-disk-images`
- **On-disk artifacts of a live/triage Windows host** — use `investigating-windows-endpoints`
- **Analyzing a known malware sample on disk** — use `analyzing-malware`
- **Writing detection rules from your memory findings** — use `engineering-detections`

## Acquisition

Acquire memory before doing anything else on a live system. Every command you
run on the box changes what is in memory. Image first, triage second.

```bash
# Linux — LiME (kernel module, minimal footprint)
sudo insmod lime-$(uname -r).ko "path=/evidence/mem.lime format=lime"
# Alternative: AVML (no kernel module needed, userspace)
sudo ./avml /evidence/mem.lime

# Windows — WinPMem (signed driver)
winpmem_mini_x64.exe mem.raw
# Alternative: DumpIt (single executable, click-to-run for non-technical staff)
DumpIt.exe /OUTPUT mem.raw /QUIET

# macOS — osxpmem
sudo osxpmem -o mem.aff4

# VM snapshots — no agent needed
# VMware:   .vmem file alongside the .vmx (suspend the VM first for consistency)
# Hyper-V:  checkpoint creates .bin and .vsv in the snapshot directory
# KVM/QEMU: virsh dump <domain> mem.raw --memory-only
# VirtualBox: VBoxManage debugvm <name> dumpvmcore --filename mem.elf

# Crash dumps — partial but sometimes all you have
# Windows:  %SystemRoot%\MEMORY.DMP (complete dump), or minidumps
# Linux:    /var/crash/, kdump output, /proc/kcore (live, pseudo-file)
```

**Hash immediately after acquisition.** Record SHA-256, source host, timestamp
(UTC), collection tool and version, and analyst name. If the image will be used
in legal or regulatory proceedings, maintain chain of custody from this point.

## Volatility 3 Workflow

Start with orientation, then follow the evidence. Do not run every plugin
blindly — each question has a plugin that answers it.

### Orientation

```bash
# Identify the OS profile and confirm the image is valid
vol -f mem.raw windows.info
vol -f mem.lime linux.bash
vol -f mem.raw banners.Banners    # fallback for unknown images
```

`windows.info` gives you the OS version, build number, and kernel base address.
If this fails, the image may be corrupt, the wrong format, or require a custom
symbol table. For Linux, you need the matching ISF (Intermediate Symbol Format)
file — generate it from the kernel debug symbols of the exact kernel version.

### Process Analysis

```bash
# Process listing — what was running
vol -f mem.raw windows.pslist     # walks the ActiveProcessLinks list
vol -f mem.raw windows.psscan     # scans for EPROCESS structures
                                          # (finds hidden/unlinked processes)
vol -f mem.raw windows.pstree     # parent-child relationships

# Compare pslist vs psscan: processes in psscan but not pslist were
# unlinked from the active list — this is DKOM or a terminated process
# that has not been fully cleaned up. Either is worth investigating.
```

**What to look for in the process list:**

- Processes with unusual parents (`svchost.exe` not under `services.exe`)
- Multiple instances of singleton processes (`lsass.exe`, `csrss.exe`)
- Processes with misspelled names (`scvhost.exe`, `lssas.exe`)
- Unexpected processes running as SYSTEM
- Processes with creation times that cluster around the suspected compromise

```bash
# DLL listing — what each process loaded
vol -f mem.raw windows.dlllist --pid <PID>
# Look for DLLs loaded from unusual paths (Temp, AppData, user-writable dirs)

# Handles — files, registry keys, mutexes, events
vol -f mem.raw windows.handles --pid <PID>
# Mutexes are especially useful: malware families often use characteristic
# mutex names to prevent re-infection
```

### Injected Code Detection

This is where memory analysis earns its keep. Disk-based forensics cannot see
code that was never written to a file.

```bash
# VAD-based detection — finds memory regions with suspicious protections
vol -f mem.raw windows.malfind
# Reports regions that are:
#   - Committed, private memory with PAGE_EXECUTE_READWRITE
#   - Containing a PE header (MZ magic) in a region not backed by a file
#   - Tagged as VadS (private) rather than VadF (file-mapped)

# Dump suspicious regions for further analysis
vol -f mem.raw windows.malfind --dump --pid <PID>
```

**Interpreting malfind results:**

- Not every RWX region is malicious — JIT compilers (.NET CLR, Java, Chrome V8)
  legitimately allocate executable memory. Filter these out by process name.
- A PE header (MZ + "This program") in an unbacked region is high confidence.
- Shellcode without a PE header is common in staged payloads — look for `0xFC`
  (`cld` instruction), `0x60` (`pushad`), or `call` + `pop` sequences at the
  start of the region.

**Hollow process detection:**

```bash
# Compare on-disk PE headers with in-memory PE headers
vol -f mem.raw windows.pslist --dump   # dump process executables
# Then compare each dumped image against the on-disk original:
#   - Different PE header = process hollowing
#   - SizeOfImage mismatch = section unmapping/remapping
#   - Entry point outside the main module = hijacked execution

# Look for processes where the PEB ImageBaseAddress does not match the
# VAD entry for the main executable — a sign of hollowing or replacement
```

### Credential Extraction

Memory contains credentials in forms that disk forensics cannot recover —
plaintext passwords (pre-Windows 10 1607 with WDigest), NTLM hashes,
Kerberos tickets, and cached domain credentials.

```bash
# SAM hashes (local accounts)
vol -f mem.raw windows.hashdump

# LSA secrets (service account passwords, auto-logon credentials, VPN)
vol -f mem.raw windows.lsadump

# Cached domain credentials (mscash2 format — crackable but slow)
vol -f mem.raw windows.cachedump

# For Kerberos tickets, dump lsass.exe memory and use mimikatz/pypykatz:
vol -f mem.raw windows.memmap --pid <lsass_pid> --dump
pypykatz lsa minidump <dumped_lsass_file>
# Yields: NTLM hashes, Kerberos TGTs and service tickets, WDigest
# plaintext (if enabled), DPAPI master keys
```

**Every credential found expands the blast radius.** Each hash or ticket
represents a lateral movement path the attacker had available. Feed these
into scoping during `responding-to-incidents`.

### Network Artifacts

```bash
# Active and recently closed connections, listening ports
vol -f mem.raw windows.netscan
# Fields: protocol, local/remote address:port, state, PID, owner process

# DNS cache: Volatility 3 has no built-in Windows DNS-cache plugin. Recover
# resolved names from process memory instead, or use a third-party plugin.
vol -f mem.raw windows.memmap --pid <PID> --dump && strings -a pid.*.dmp | grep -iE '\.(com|net|org|ru|cn)\b'

# Linux equivalent
vol -f mem.lime linux.sockstat
```

**What to look for:**

- Connections to external IPs from unexpected processes (especially
  `svchost.exe`, `rundll32.exe`, `regsvr32.exe`)
- Listening ports on unusual numbers — backdoors often bind to high ports
- Connections from processes that no longer appear in pslist (terminated
  C2 channels visible only in memory)
- Correlate remote IPs against threat intel feeds immediately

### Command History and Console Output

```bash
# Command-line arguments for every process
vol -f mem.raw windows.cmdline
# Reveals encoded PowerShell commands, lateral movement tool arguments,
# reconnaissance commands, and data staging operations

# Console input/output buffers (cmd.exe sessions)
vol -f mem.raw windows.consoles
# Can recover full command history and output even after the window is closed

# Linux shell history from memory (survives history -c)
vol -f mem.lime linux.bash
```

Encoded PowerShell is common. Decode `-EncodedCommand` arguments:

```bash
echo "<base64_string>" | base64 -d | iconv -f UTF-16LE -t UTF-8
```

## Timeline Construction from Memory

Combine process creation times, network connections, and handle timestamps
to build a memory-only timeline. This timeline captures events that never
touched disk.

```
UTC Timestamp        | Artifact        | Detail                          | PID
2026-07-10 02:14:02  | Process create  | cmd.exe via explorer.exe        | 4812
2026-07-10 02:14:08  | Process create  | powershell.exe via cmd.exe      | 5104
2026-07-10 02:14:09  | Network conn    | 5104 -> 203.0.113.50:443 EST   | 5104
2026-07-10 02:14:15  | Process create  | rundll32.exe (no DLL in cmdline)| 6220
2026-07-10 02:14:15  | malfind hit     | RWX region with PE header       | 6220
2026-07-10 02:14:22  | Network conn    | 6220 -> 198.51.100.10:8443 EST | 6220
```

Merge this with disk and log timelines from `responding-to-incidents` to fill
gaps. Memory gives you what ran; disk gives you what persisted; logs give you
what was recorded. None of the three is complete alone.

## Rootkit Detection

Kernel-mode rootkits modify OS structures to hide processes, files, registry
keys, and network connections. Memory analysis is the primary detection method
because the rootkit cannot hide from a raw memory image.

```bash
# SSDT hooking — System Service Descriptor Table
vol -f mem.raw windows.ssdt
# Entries pointing outside ntoskrnl.exe or win32k.sys are hooked

# Driver and module enumeration
vol -f mem.raw windows.driverscan    # scan for DRIVER_OBJECT
vol -f mem.raw windows.modules       # loaded kernel modules
vol -f mem.raw windows.modscan       # scan for unlinked modules
# Modules in modscan but not modules = hidden drivers

# Callbacks — rootkits register notify routines to intercept operations
vol -f mem.raw windows.callbacks

# IDT — Interrupt Descriptor Table modifications. Volatility 3 ships this for
# Linux only (linux.check_idt); there is no windows.idt. On Windows, IDT hooking
# is largely a pre-PatchGuard (x86) technique — check SSDT and callbacks above.
vol -f mem.lime linux.check_idt
# Handlers pointing to addresses outside known kernel modules are suspicious
```

**DKOM (Direct Kernel Object Manipulation):**

- Process unlinking: removes EPROCESS from ActiveProcessLinks
- Detected by comparing pslist (walks the list) vs psscan (carves memory)
- The same principle applies to threads, drivers, and other kernel objects

## Linux-Specific Analysis

```bash
# Process listing
vol -f mem.lime linux.pslist
vol -f mem.lime linux.pstree
vol -f mem.lime linux.psaux         # with command-line arguments

# Shell history recovered from process memory
vol -f mem.lime linux.bash

# ELF binaries in memory — find injected shared objects
vol -f mem.lime linux.elfs

# Syscall table integrity — detect syscall hooking
vol -f mem.lime linux.check_syscall
# Entries not pointing to the expected kernel text range are hooked

# Loaded kernel modules and hidden modules
vol -f mem.lime linux.lsmod
vol -f mem.lime linux.hidden_modules

# Open files and network connections
vol -f mem.lime linux.lsof
vol -f mem.lime linux.sockstat

# Mounted filesystems and their types
vol -f mem.lime linux.mountinfo
```

**Symbol tables for Linux:** Unlike Windows, Linux has no fixed kernel
structures. You must provide an ISF file matching the exact kernel version.
Generate it with `dwarf2json` from the kernel's debug symbols
(`vmlinux` with DWARF info). Without the correct symbols, Volatility will
either fail or produce garbage output.

## Strings and YARA Scanning

When you do not know what you are looking for, or need to validate a
hypothesis across the entire image.

```bash
# YARA rules against the full image
vol -f mem.raw yarascan.YaraScan --yara-file rules.yar
# Scoping to a specific process:
vol -f mem.raw yarascan.YaraScan --yara-file rules.yar --pid <PID>

# Strings extraction — raw approach, still useful
strings -a -t d mem.raw > strings_ascii.txt
strings -a -t d -e l mem.raw > strings_unicode.txt
# Search for IPs, URLs, commands, known malware strings

# bulk_extractor — automated structured-data carving
bulk_extractor -o be_output mem.raw
# Produces: emails, URLs, credit card numbers, domain names, IP addresses,
# JSON/XML fragments, and other structured data, each in a separate file
# Use the histogram files (url_histogram.txt, domain_histogram.txt) first —
# stacking by frequency surfaces C2 domains and unusual patterns
```

**YARA rules for memory analysis should differ from file-based rules.**
Packed or encrypted payloads on disk are decrypted in memory, so write rules
for the unpacked form. Also target strings that only appear at runtime:
mutex names, C2 URLs, API resolution strings, and decrypted configuration
blocks.

## Rationalizations to Reject

- *"The disk image is enough."* Disk forensics cannot see injected code,
  in-memory-only payloads, decrypted configurations, or credentials that were
  never written to disk. Memory is a different evidence source, not a redundant
  one.
- *"The memory dump is too large to analyze efficiently."* Start with targeted
  plugins — pslist, malfind, netscan, cmdline — not a full strings dump. Five
  plugins will answer more than a grep through 64 GB of raw data.
- *"We can just re-image and move on."* Re-imaging destroys the only copy of
  volatile evidence. If you need to know what the attacker did, you need the
  memory.
- *"Malfind flagged it, so it is malicious."* Malfind reports suspicious memory
  protections, not confirmed malware. JIT engines, .NET assemblies, and some
  security tools produce legitimate RWX regions. Validate every hit.
- *"We don't have the right Volatility profile."* For Linux, build the ISF from
  the target kernel's debug symbols. For Windows, Volatility 3 auto-detects
  most versions. An unsupported profile is a solvable problem, not a reason to
  skip memory analysis.
- *"The system was rebooted, so memory evidence is gone."* Check for crash
  dumps, hibernation files (`hiberfil.sys`), page files (`pagefile.sys`), and
  VM snapshots. These contain partial memory contents and are often overlooked.
- *"Strings output is too noisy to be useful."* Use bulk_extractor histograms,
  YARA rules, or grep for specific indicators. Raw strings is a last resort,
  not a first step.

## References

- `responding-to-incidents` — broader IR methodology and evidence handling
- `analyzing-malware` — deep analysis of samples extracted from memory
- `engineering-detections` — writing rules from TTPs discovered in memory
- `hunting-threats` — proactive search using indicators found in memory analysis
