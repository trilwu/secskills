---
name: analyzing-shellcode
description: Analyze raw shellcode and position-independent code — extracting the bytes, guessing architecture, disassembling at the right base, decoding self-decoder stubs, resolving hashed Windows APIs, emulating to the decoded stage, and pulling C2 and stage IOCs. Use when handed a raw blob of position-independent code, an extracted payload with no PE/ELF header, shellcode lifted from an exploit or a macro/loader, a `\x`-escaped or base64 buffer, a suspected Cobalt Strike or Metasploit stager, or an egg-hunter.
---

# Analyzing Shellcode

Shellcode is code with no container — no PE/ELF header, no imports table, no
fixed load address — so it must find everything it needs at runtime. That
self-reliance is exactly what gives it away: the PEB walk, the API hashing,
the position-independent GetPC trick are structural fingerprints you can read
even before you know what the payload does.

## When to Use

- A raw blob of position-independent code with no PE/ELF/Mach-O header
- A payload carved from an exploit, a macro, a loader, or a JS/HTA dropper
- A `\x`-escaped, `0x`-prefixed, base64, or XOR-obfuscated byte buffer
- A suspected Metasploit stager (reverse_tcp/https) or Cobalt Strike beacon stage
- An egg-hunter or GetPC/decoder stub found while triaging a larger binary
- Bytes recovered from network capture, RWX memory, or a document stream

## When NOT to Use

- **The sample is a normal PE/ELF/Mach-O with headers** — use
  `analyzing-binaries` for the loader-backed disassembly workflow
- **You need broader sample triage or family ID** — use `analyzing-malware`;
  come here only for the raw payload stage inside it
- **The blob is a packed executable, not raw shellcode** — use
  `unpacking-protected-binaries` to unwrap it first
- **You are carving the shellcode out of a memory dump first** — use
  `analyzing-memory-images` to locate and extract the region, then return here
- **Deep static reversing once decoded** — `reverse-engineering` is not a
  skill; route sustained disassembly work back to `analyzing-binaries`

## Get the Bytes First

Shellcode arrives wrapped. Normalize it to a flat binary before anything else.

```bash
# \x-escaped or 0x C-array pasted from an exploit → raw bytes
python3 -c "import sys,re; d=open('sc.txt').read(); \
  b=bytes(int(x,16) for x in re.findall(r'(?:0x|\\\\x)([0-9a-fA-F]{2})',d)); \
  open('sc.bin','wb').write(b); sys.stderr.write(f'{len(b)} bytes\n')"

# base64 buffer
base64 -d payload.b64 > sc.bin

# single-byte XOR brute (find the key that yields printable / low entropy)
python3 -c "import sys; d=open('sc.bin','rb').read(); \
  [print(k, bytes(c^k for c in d[:16]).hex()) for k in range(256)]"
```

Then sniff what you have before disassembling:

```bash
file sc.bin && wc -c < sc.bin           # size: stagers ~200-800B, stages tens of KB
ent sc.bin 2>/dev/null || binwalk -E sc.bin   # high entropy → encoded/self-decoder
```

For document- and capture-borne shellcode, extract first: `olevba --deobf`
for Office macros (`analyzing-malware` covers this), and carve from PCAP with
`tshark -r c.pcap --export-objects http,out/` or a `tcp.stream` follow, then
treat the bytes as above.

## First-Look Triage

```bash
xxd sc.bin | head -40
```

Read the head for structure, not meaning:

- **Architecture guess.** x86 shows `55 8B EC` prologues, `64 A1 30 00` /
  `64 8B` (`fs:[0x30]`) PEB access, and `E8 00000000 5x` call/pop. x64 shows
  `65 48 8B` (`gs:[0x60]`), REX-prefixed `48 ...`, and RSP alignment `48 83 EC`.
  ARM/AArch64 is uniform 4-byte words with no x86 prologue signature.
- **GetPC trick.** `E8 00 00 00 00 58/59/5A/5B/5E` (call $+5 then pop) or the
  `fnstenv` / `D9 EE D9 74 24 F4 5B` FPU trick recovers EIP for
  position-independence. Its presence means the code relocates itself and a
  decoder often follows.
- **Egg-hunter tags.** Repeated 8-byte marker like `w00tw00t` (`77 30 30 74`
  ×2) is an egg-hunter searching memory for the real payload.
- **Null-free / alnum encoding.** No `00` bytes, or all-printable bytes, means
  an encoder stub (Metasploit `alpha_mixed`, `shikata_ga_nai`) wraps the real
  code — you are looking at the decoder, not the payload.

## Static Disassembly at the Right Base

The single most common mistake is disassembling at the wrong architecture or
mid-instruction. Try both widths and read which one produces a sane prologue.

```bash
# objdump on a raw blob — set the arch explicitly, Intel syntax
objdump -D -b binary -m i386        -M intel sc.bin     # 32-bit
objdump -D -b binary -m i386:x86-64 -M intel sc.bin     # 64-bit

# ndisasm — quick, and -e skips a leading offset if the entry is not at 0
ndisasm -b 32 sc.bin
ndisasm -b 64 sc.bin

# rizin / radare2: assemble/disassemble a blob directly
rasm2 -a x86 -b 32 -d "$(xxd -p sc.bin | tr -d '\n')"
r2 -a x86 -b 32 -m 0x400000 sc.bin      # load raw at a base
#   e asm.arch=x86 ; e asm.bits=32 ; s 0 ; pd 60      disassemble entry
#   pdf @ 0                                            treat entry as a function
```

To load raw shellcode in Ghidra/IDA/Cutter: import as a **raw binary**, set the
processor (x86:LE:32 or x86:LE:64), pick a base address, and **define an entry
point / disassemble at the true first instruction** — not offset 0 if a length
prefix or junk sled precedes it. Without a defined entry the auto-analyzer will
disassemble data as code and the listing is noise.

## Decode Self-Decoders

Encoded shellcode is a small decoder stub followed by an encrypted body. Do not
try to read the body statically — disassemble only the stub, then let it run.

- **Recognize the stub.** A short loop with `xor`/`add`/`sub`/`rol` against a
  running pointer, a length counter, and a key or key schedule. The loop's tail
  jumps back until the counter hits zero, then falls through into the decoded
  body.
- **shikata_ga_nai.** Metasploit's polymorphic feedback XOR decoder: a GetPC
  block, then an XOR loop where each key word is mutated by the previous
  plaintext (additive feedback). It re-encodes differently every build, so a
  byte signature will not match — decode it by executing it, not by patterning.
- **Let it decode itself.** Emulate or single-step the stub and dump memory once
  the loop exits; the region it wrote is the real stage. Then disassemble that.

```bash
# scdbg dumps the decoded buffer and unpacks the second stage for x86 Windows
scdbg -f sc.bin -s -1                     # -s -1 lifts the step limit (default 2M)
scdbg -f sc.bin -d                       # dump self-modified/decoded memory
```

## Windows API Resolution by Hash

Shellcode has no imports, so it walks the loaded-module list and resolves APIs
by a hash of their names. Recognizing this is often the whole analysis.

- **PEB walk.** `fs:[0x30]` (x86) or `gs:[0x60]` (x64) loads the PEB, then
  `PEB->Ldr->InMemoryOrderModuleList` is traversed to find `kernel32.dll` (or
  `ntdll.dll`) without a hardcoded address.
- **Export hashing.** For each export name the stub computes a hash — commonly
  `ror13` additive (the classic Metasploit `block_api`) or `djb2` — and compares
  against a 4-byte constant. The constant *is* the API name, once you invert it.
- **Map hashes back to names.** Precompute the hash over every export in the
  system DLLs and look up the constants you see:

```bash
# Reproduce ror13 (Metasploit) and match a target constant to an export name
python3 - <<'PY'
def ror13(s):
    h=0
    for c in (s+'\0').encode('ascii'):
        h=((h>>13)|(h<<19))&0xffffffff; h=(h+c)&0xffffffff
    return h
for api in ("LoadLibraryA","GetProcAddress","WinExec","VirtualAlloc"):
    print(hex(ror13(api)), api)
PY
```

Tools: `scdbg` prints resolved API calls with arguments as it emulates;
`jmp2it`/`blob_runner` under a debugger let you break at the resolver; export
tables come from `dllexp` or `rabin2 -E kernel32.dll`. When the hash algorithm
is custom, lift it into the Python harness and brute the export lists.

## Emulation Is the Fast Path

For Windows x86 shellcode, emulation resolves the APIs, decodes the stages, and
prints the behavior in seconds — reach for it before manual tracing.

```bash
# scdbg — emulates x86 Windows shellcode, reports API calls, C2, and stages
scdbg -f sc.bin                          # default trace of resolved API calls
scdbg -f sc.bin /findsc                  # brute-force the correct start offset
scdbg -f sc.bin -foff 0x1a               # force entry at a known offset

# speakeasy — emulate x86/x64 shellcode or a raw module
speakeasy -t sc.bin --raw --arch x86     # --raw shellcode, --arch x86|amd64
speakeasy -t sc.bin --raw --arch amd64 -o report.json
```

For custom logic or non-Windows targets, build a harness:

- **Unicorn** — map memory, set the registers, hook `code`/`mem` events, run,
  and read the decoded region back. Best when you need to script the decode.
- **Qiling** — higher-level; emulates the OS layer so hashed-API resolution and
  `VirtualAlloc`/`WinExec` behave, with a rootfs and syscall interception.
- **Run under a debugger.** `blob_runner`, `shellcode2exe`, or `jmp2it` wrap the
  blob into a loadable stub; open it in **x32dbg/x64dbg**, set EIP/RIP to the
  entry, and single-step through the decoder to the live stage.

## Identify the Stage and Family

- **Metasploit stagers.** `reverse_tcp` builds a socket then `recv`s a second
  stage into RWX memory and jumps to it; `reverse_https` uses `WinInet`
  (`InternetOpen`/`HttpOpenRequest`). scdbg/speakeasy surface the connect
  address and port directly.
- **Cobalt Strike.** The beacon stage carries an encoded configuration; once
  decoded, parse it for C2 hosts, ports, URIs, user-agent, sleep/jitter, and
  the malleable profile. Community parsers (e.g. beacon config extractors) read
  the config block; hand a confirmed beacon to `analyzing-malware`.
- **Extract the endpoint.** From the emulator log or the decoded config pull the
  C2 host/port and the request URI — these are the immediate blocking IOCs.
- **Compare against known decoders.** shikata, `call4_dword_xor`, `alpha_mixed`,
  and the `block_api` resolver have recognizable shapes; matching one names the
  toolkit and tells you what the following bytes must be.

## Safe Execution Discipline

Emulation is safe; actually running the shellcode is detonation. Apply the same
containment `analyzing-malware` requires.

- Isolated VM, snapshot taken before execution, reverted after.
- No network, or a faked C2 (INetSim/FakeNet-NG) so the stager's callback
  resolves to your listener rather than the live operator.
- Never let a stager reach the real C2 on an active incident — the callback
  tells the operator you are looking, and a second-stage download is a
  disclosure of your analysis.

## Pull IOCs and Hand Off

Collect the durable indicators as you decode: C2 host/IP, port, request URI and
user-agent, mutex names, the decoder key or hash constants, and the egg tag.
Rank them as `analyzing-malware` does — behavior and config outlive rotating
hosts.

Then route the work:

- A byte/structure signature for the decoder or resolver → `writing-yara-rules`
  (author the rule), then `engineering-detections` (deploy it)
- The dropped or downloaded second stage → `analyzing-malware`
- Sustained disassembly of a large decoded stage → `analyzing-binaries`
- Writing up the finding → `reporting-security-findings`

## Rationalizations to Reject

- *"objdump showed garbage, so it's encrypted."* More likely you disassembled
  at the wrong architecture, at the wrong offset, or straight through a decoder
  stub. Try both bit-widths and find the offset with a sane prologue first.
- *"There are no imports, so I can't tell what it calls."* Shellcode resolves
  APIs by hash. Find the PEB walk and invert the hash constants.
- *"I'll just run it to see what it does."* Not without an isolated,
  network-controlled harness. Emulate with scdbg/speakeasy instead.
- *"A byte signature will catch this stager."* Not a polymorphic one —
  shikata_ga_nai re-encodes every build. Signature the decoded stage or the
  structural resolver, not the encoder.
- *"No obvious C2 in the strings."* The address is built at runtime and the
  config is encoded. Decode the stub, then emulate to read the connect call.
- *"It starts at offset 0."* Often it does not — a length prefix, alignment
  sled, or GetPC block precedes the entry. Use `/findsc` or read for the true
  first instruction.
- *"The disassembler auto-analyzed it, so the listing is right."* On a headerless
  blob the analyzer guesses the entry and treats data as code. Define the real
  entry and processor, or the whole listing is misaligned.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Defense Evasion** (TA0005)

- [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information — see also `analyzing-malware`, `analyzing-binaries`
- [T1140](https://attack.mitre.org/techniques/T1140/) Deobfuscate/Decode Files or Information — see also `analyzing-malware`, `analyzing-binaries`
- [T1620](https://attack.mitre.org/techniques/T1620/) Reflective Code Loading — see also `analyzing-malware`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `analyzing-binaries` — disassembler workflow for the decoded stage
- `analyzing-malware` — sample triage, containment, family ID, and the dropped stage
- `analyzing-memory-images` — carving shellcode out of a memory dump first
- `writing-yara-rules` — authoring a durable signature for the decoder or decoded stage
- `engineering-detections` — turning a decoder/resolver signature into deployed rules
- `reporting-security-findings` — writing up the analysis
- scdbg, speakeasy, Unicorn, Qiling for emulation
- radare2/rizin (`rasm2`/`pd`), Cutter for static disassembly of raw blobs
- x64dbg/x32dbg with blob_runner / shellcode2exe / jmp2it to run under a debugger
