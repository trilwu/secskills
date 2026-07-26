---
name: analyzing-binaries
description: Reverse engineer compiled binaries, firmware, and mobile app packages using triage, static disassembly, decompilation, and dynamic instrumentation. Use when analyzing an executable, ELF/PE/Mach-O file, firmware image, or stripped binary, recovering an algorithm or protocol, or working a CTF reversing challenge.
---

# Analyzing Binaries

Reverse engineering is hypothesis testing against a program you cannot read.
The cost of the job is dominated by how much code you look at, so the whole
discipline is about narrowing: triage first, find the interesting few percent,
then read that carefully.

## When to Use

- Understanding what an unknown or undocumented executable does
- Recovering an algorithm, file format, or wire protocol from a binary
- Locating a vulnerability in a closed-source target
- Firmware analysis for embedded and IoT devices
- Reversing challenges in CTFs

## When NOT to Use

- **Live malware with intent to detonate** — use `analyzing-malware`, which
  covers containment and safe detonation. Come back here for the disassembly.
- **Source is available** — use `auditing-code-for-vulnerabilities`
- **Android/iOS app assessment as a whole** — use `testing-mobile-applications`;
  use this skill for the native `.so`/Mach-O components inside it

## Triage First — Never Open a Disassembler Cold

Every minute here saves an hour in the decompiler.

```bash
file target && du -h target
# Architecture, endianness, PIE, stripped or not — all decide your tooling
readelf -hSd target        # ELF: headers, sections, dynamic deps
rabin2 -I target           # radare2's normalized summary of any format
objdump -p target          # PE/ELF imports and load config

# Protections tell you what the author expected
checksec --file=target     # NX, canary, RELRO, PIE, Fortify

# Strings, but read them for structure rather than skimming
strings -n 8 -t x target | less        # ASCII with offsets
strings -e l -n 8 target               # UTF-16LE, essential on Windows
```

**What triage should answer before you disassemble:**

| Question | Signal |
| --- | --- |
| What language/toolchain built this? | Rust/Go runtime strings, `libstdc++`, `__gxx_personality`, MSVC RTTI |
| Is it packed? | High entropy, tiny import table, sections named `UPX`, `.themida` |
| What does it talk to? | Imports of socket/HTTP APIs, embedded URLs, cert blobs |
| Where is the interesting logic? | Imports of crypto/file/registry/process APIs |
| Is it stripped? | `nm -D` empty, no `.symtab` |

```bash
# Entropy scan finds packed or embedded-blob regions
binwalk -E target
# Unpack the common case
upx -d target -o target.unpacked
```

Go and Rust binaries are usually not stripped in the ways that matter. Recover
symbols before doing anything else — it changes the job from hours to minutes.

```bash
# Go: recover function names and types
GoReSym -t -p target > syms.json    # or the redress / IDAGolangHelper plugins
# Rust: demangle
nm -C target 2>/dev/null | head
```

## Static Analysis Workflow

Pick one tool and go deep; switching tools mid-analysis loses your annotations.

```bash
# Ghidra headless: batch import, auto-analyze, run a script
analyzeHeadless /proj MyProj -import target -postScript Decompile.java

# radare2 / rizin interactive
r2 -AA target
# aaa            analyze everything
# afl            list functions, sorted by size — big ones first
# axt @ sym.f    cross-references TO a function (who calls this?)
# pdg @ main     decompile with ghidra plugin (r2ghidra)
# iz / izz       strings in data / whole binary
# /x deadbeef    search for a byte pattern

# Binary Ninja / IDA headless equivalents exist; the workflow is identical
```

**Navigate by evidence, not by address order.** The three entry points that
find the interesting code fastest:

1. **Strings → xrefs.** Find a message you saw at runtime, cross-reference it,
   land in the function that produced it.
2. **Imports → xrefs.** Cross-reference `recv`, `CreateProcess`, `fopen`,
   `EVP_EncryptInit` to find the code that does the thing you care about.
3. **Entropy/constants.** Crypto constants (AES S-box, SHA-2 round constants,
   MD5 magic) are recognizable; `binwalk`, `findcrypt`, and YARA rules locate them.

Then read outward from that anchor. Rename every function and variable as you
work out what it does — a decompiler listing you have annotated is a completely
different artifact from a raw one.

## Recognizing Structure in Decompiler Output

The decompiler gives you C-shaped noise. What you are looking for:

- **Loop with an index into a byte array and an XOR** — obfuscation or a
  homebrew cipher. Extract the key, decode offline.
- **A switch on a small integer read from input** — command dispatch. This is
  usually the protocol, and it is the map for everything else.
- **`memcpy` with a length that came from the input** — start of a memory
  safety review; see `auditing-code-for-vulnerabilities`.
- **Repeated `[rax + 8*n]` accesses on the same base** — a struct. Define it in
  the tool; the listing collapses to readable code.
- **A call through a register right after a table load** — vtable or callback
  dispatch. Recover the table to recover the class.

## Dynamic Analysis

Static tells you what the code can do; dynamic tells you what it does. Run
untrusted binaries only in an isolated VM with no host shares and networking
under your control — see `analyzing-malware` for the containment procedure.

```bash
# Syscall and API-level behaviour
strace -f -e trace=network,file,process -o trace.log ./target
ltrace -f ./target
# Windows equivalents: API Monitor, Procmon, drltrace

# Debugging
gdb -q ./target       # with pwndbg/GEF: `checksec`, `vmmap`, `heap`, `telescope`
lldb ./target         # macOS
x64dbg / WinDbg       # Windows

# Instrumentation — the highest-leverage dynamic technique
frida-trace -f ./target -i 'recv*' -i 'EVP_*'
# then edit the generated JS handlers to dump buffers and patch return values
```

Frida is the fastest route through anti-debugging, custom crypto, and license
checks: hook the function *after* decryption rather than defeating the
obfuscation that protects it.

**Emulation** for firmware and isolated routines:

```bash
qemu-arm -L /usr/arm-linux-gnueabi ./target      # user-mode
# Unicorn for a single function: map memory, set registers, run, read result
# angr for symbolic execution when you need an input that reaches a state
```

## Firmware

```bash
binwalk -Me firmware.bin        # extract recursively
# Identify the filesystem before extracting: squashfs, jffs2, cramfs, ubifs
unsquashfs -d rootfs squashfs-root.bin

# Then treat the rootfs as a Linux system
rg -n 'password|admin|BEGIN (RSA|OPENSSH) PRIVATE KEY|api[_-]?key' -i rootfs/
find rootfs -name '*.pem' -o -name 'shadow' -o -name '*.conf'
# Web interface and startup scripts are where the bugs are
ls rootfs/etc/init.d rootfs/www rootfs/usr/sbin
```

For a bootloader or bare-metal image with no filesystem, find the load address
(often in the vendor SDK or derivable from absolute-pointer clustering) before
disassembling — a wrong base address makes the whole listing meaningless.

## Anti-Analysis

Recognize it, then decide whether to defeat it or route around it.

| Technique | Recognition | Response |
| --- | --- | --- |
| Packing | High entropy, stub + one big section | Unpack, or dump from memory after the OEP |
| Anti-debug | `IsDebuggerPresent`, `ptrace(PTRACE_TRACEME)`, timing checks | Patch the check, or hook it with Frida |
| VM detection | CPUID checks, MAC OUI, registry artifacts | Harden the VM, or patch the detector |
| String obfuscation | No readable strings but obvious decode loops | Emulate the decoder over all call sites |
| Control-flow flattening | Giant switch on a state variable | Symbolic deobfuscation, or ignore and work dynamically |

Routing around is usually cheaper. If a check is defeating you statically,
hook the function that consumes its result.

## Rationalizations to Reject

- *"I'll read the whole binary."* You will not. Triage and anchor, or you burn
  the engagement on library code.
- *"The decompiler output is wrong, so this is a dead end."* Decompiler output
  is frequently wrong around calling conventions and structs. Check the
  disassembly for the specific instruction before drawing a conclusion.
- *"It's stripped, so symbols are gone."* Library functions are recoverable
  (FLIRT/Sigs, `bindiff` against a compiled reference), and Go/Rust metadata
  usually survives.
- *"I'll just run it to see what it does."* Not before you know whether it is
  hostile and where it is contained.
- *"The strings tell the story."* Strings tell you where to look. Attackers
  plant misleading ones.

## Deliverable

An RE report should let a reader act without repeating your work:

- **Identity** — hashes, file type, architecture, compiler, packer
- **Capability** — what it does, expressed as behaviour, not addresses
- **Key routines** — annotated addresses with a name and a one-line purpose
- **Protocol/format** — field-by-field, with a parser or Kaitai spec if useful
- **Indicators** — network endpoints, file paths, mutexes, keys, constants
- **Open questions** — what you did not resolve, and why

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Defense Evasion** (TA0005)

- [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information — see also `analyzing-malware`
- [T1027.002](https://attack.mitre.org/techniques/T1027/002/) Software Packing — see also `analyzing-malware`
- [T1140](https://attack.mitre.org/techniques/T1140/) Deobfuscate/Decode Files or Information — see also `analyzing-malware`
- [T1497](https://attack.mitre.org/techniques/T1497/) Virtualization/Sandbox Evasion — see also `analyzing-malware`
- [T1622](https://attack.mitre.org/techniques/T1622/) Debugger Evasion — see also `analyzing-malware`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `analyzing-malware` — containment, detonation, and IOC extraction
- `testing-mobile-applications` — APK/IPA workflows around native components
- Ghidra, rizin/radare2, Binary Ninja, IDA — pick one and learn it deeply
- Frida, angr, Unicorn, QEMU for dynamic and emulated analysis
