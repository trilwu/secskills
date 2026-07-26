---
name: unpacking-protected-binaries
description: Unpack and dump protected executables — UPX and commodity packers, custom crypters, commercial protectors like Themida and VMProtect, and .NET packers — by finding the original entry point, dumping from memory, and rebuilding the import table with Scylla, pe-sieve, or x64dbg. Use when a binary has high entropy, few imports, unnamed sections, or when analysis tools show almost no code.
---

# Unpacking Protected Binaries

Static unpacking is a trap for anything beyond UPX. The reliable method is to
let the program unpack itself, then take the result out of memory. Almost every
protector, however sophisticated, must eventually produce executable code in a
readable page — that moment is what you are waiting for.

Run protected samples only in a contained environment; see `analyzing-malware`.

## When to Use

- `binwalk -E` shows uniformly high entropy across most of the file
- The import table has a handful of entries (`LoadLibrary`, `GetProcAddress`)
- Section names are absent, random, or `UPX0`/`.themida`/`.vmp0`
- Disassembly shows a small stub and one large data blob
- A tool reports the file is packed, or analysis finds essentially no code

## When NOT to Use

- **The wider malware workflow** — use `analyzing-malware` for containment,
  triage, and IOC output; come back here for the unpacking step
- **.NET assemblies** — use `analyzing-dotnet-assemblies`, which covers .NET
  packers and managed memory dumping specifically
- **Obfuscation without packing** (readable imports, normal entropy, confusing
  control flow) — use `analyzing-binaries`
- **Firmware images** — `binwalk -Me` extraction is a different job; see
  `analyzing-binaries`

## Identify the Protector First

The response differs enormously between a commodity packer and a commercial
protector, so spend a minute here.

```bash
diec target.exe                     # Detect It Easy — the best single identifier
rg -a -o 'UPX|MPRESS|Themida|VMProtect|ASPack|Enigma|Obsidium|PECompact' target.exe
binwalk -E target.exe               # entropy profile
```

```bash
# Structural tells
readpe target.exe                   # or: rabin2 -S target.exe
#   raw size ≈ 0 with large virtual size   → section unpacked at runtime
#   section marked writable AND executable → self-modifying
#   entry point outside the first section  → stub in a later section
#   TLS callbacks present                  → code runs BEFORE the entry point
```

**TLS callbacks matter.** They execute before the entry point, so a debugger
set to break at the EP has already run the protector's anti-debug checks. Set
the debugger to break on TLS callbacks, not on the entry point.

| Identified as | Approach |
| --- | --- |
| UPX (unmodified) | `upx -d` — takes seconds |
| UPX (modified header) | Repair the magic, or unpack dynamically |
| Commodity crypter, custom stub | Dynamic dump at OEP |
| Themida, VMProtect, Enigma | Dump plus heavy import repair; expect virtualized functions to stay virtualized |
| .NET packer | `analyzing-dotnet-assemblies` |

```bash
upx -d target.exe -o unpacked.exe          # try first, costs nothing
```

## The Dynamic Unpacking Loop

```
1. Break before the stub runs (TLS callbacks, or the EP if none)
2. Run until the unpacked code exists in memory
3. Find the OEP — the original entry point of the real program
4. Dump the process image
5. Rebuild the import table
6. Fix the PE headers and verify the dump loads
```

**Finding the OEP** is the part that takes judgment. Reliable signals:

- **Memory write-then-execute.** Set a hardware breakpoint on execute over the
  section the stub is writing into. The first execution there is usually at or
  near the OEP. In x64dbg this is a page guard on the target section.
- **The tail jump.** Packer stubs end with a jump far outside the stub's own
  section. Step to the end of the stub and watch for the long jump.
- **Compiler entry signature.** Real entry points look like a compiler's CRT
  startup — `security_init_cookie`, a call to `__scrt_common_main`, or a
  standard prologue. When execution lands somewhere that looks like normal
  compiled code rather than obfuscated stub code, you have arrived.
- **`GetCommandLine` / `GetModuleHandle` calls** early in the real program.

```
x64dbg workflow:
  Options → Events → break on TLS callbacks and on system breakpoint
  Run, then in the Memory Map set "Break on execute" for the target section
  When it breaks, confirm the code looks compiler-generated → that is the OEP
```

## Dumping and Import Repair

```bash
# Dump from the debugger at OEP: Scylla (built into x64dbg)
#   1. Attach / already broken at OEP
#   2. Scylla → set OEP → IAT Autosearch → Get Imports
#   3. Fix invalid/unresolved entries, then Dump + Fix Dump

# Or dump externally
pe-sieve /pid <pid> /dmode 3        # dumps and repairs; good for automation
# hollows_hunter for scanning a whole system for unpacked/injected modules
```

**Import repair is where most dumps fail.** Packers replace the import table
with a runtime-resolved stub, so a raw dump has API calls pointing into the
packer's own thunk area. Scylla's IAT search finds the resolved table; when it
returns unresolved entries, that usually means:

- The dump was taken before the imports were fully resolved — run further
- The protector uses API redirection, where each call goes through an obfuscated
  stub that computes the real address — these need manual resolution or an
  emulation-based unstubber
- The API is resolved lazily on first call — trigger the functionality, then dump

Verify the dump before analyzing it:

```bash
readpe dumped.exe | head -30          # sane headers, correct EP
rabin2 -i dumped.exe | head -20       # imports resolve to real API names
# The strongest test: does it run, or does a decompiler produce sane output?
```

## Commercial Protectors

Themida, VMProtect, Enigma, and similar do more than pack. Expect:

- **Virtualized functions.** Selected functions are converted to bytecode for a
  custom VM. Dumping recovers the program *around* them, but the virtualized
  functions remain a VM interpreter loop. Devirtualization is a research-scale
  effort per protector version.
- **Aggressive anti-debug and anti-VM.** Handle detection first —
  ScyllaHide, TitanHide, or a hypervisor-level debugger — or the process will
  exit or corrupt itself before you reach OEP.
- **Multiple unpacking stages** with re-encryption of earlier stages.

The practical decision: if only a few functions are virtualized, dump and
analyze everything else, then handle those functions **dynamically** — hook
their inputs and outputs rather than reading their logic. That answers "what
does it do" without defeating the VM.

## When Dumping Is Not Available

Some samples never fully unpack in one place: they decrypt individual functions
on demand and re-encrypt after use, or they run entirely from a JIT-style
buffer.

- **Trace-based recovery.** Record execution with an instrumentation framework
  and reconstruct the executed code path from the trace.
- **Hook the decryption routine** and log every plaintext block as it is
  produced — you get the code piecemeal but complete.
- **Frida/Pin/DynamoRIO** for the instrumentation.

## Rationalizations to Reject

- *"`upx -d` failed, so it isn't UPX."* Modified UPX headers are the most
  common commodity evasion. Check the section names and stub pattern.
- *"I'll write a static unpacker."* Worth it for one family you will see a
  thousand times. Otherwise dumping is an order of magnitude cheaper.
- *"The dump won't run, so it's wrong."* Verify what you actually need. Many
  dumps are unrunnable but perfectly analyzable.
- *"Imports are broken, dump is useless."* Re-dump later in execution, or
  resolve manually. Timing is usually the issue.
- *"It's VMProtect, so it's impossible."* Only the virtualized functions are.
  Dump everything else and treat those as black boxes with observable I/O.
- *"I'll set a breakpoint on the entry point."* TLS callbacks already ran.
- *"Nothing happened when I ran it."* Anti-VM or anti-debug fired. Handle
  detection before unpacking.

## References

- `analyzing-malware` — containment, capability model, IOCs; the workflow this fits into
- `analyzing-binaries` — post-unpacking analysis and anti-analysis handling
- `analyzing-dotnet-assemblies` — .NET packers and managed dumping
- Detect It Easy, x64dbg + Scylla + ScyllaHide, pe-sieve, hollows_hunter, UPX
