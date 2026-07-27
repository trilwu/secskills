---
name: analyzing-dotnet-assemblies
description: Reverse engineer .NET assemblies and executables with dnSpyEx, ILSpy, and de4dot — identifying and unwrapping obfuscators and packers, deobfuscating control flow and string encryption, handling single-file and NativeAOT publishes, and patching IL. Use when a binary is a managed PE, when ILSpy shows mangled names or empty method bodies, or when analyzing .NET malware, a loader, or a Windows application.
verified: 2026-07-27
---

# Analyzing .NET Assemblies

.NET compiles to IL with full metadata, so an unobfuscated assembly
decompiles to near-original C#. That makes the interesting question not "how do
I read this" but "what is in the way" — a packer, an obfuscator, a runtime
loader, or a publish mode that hides the managed code inside a native host.

## When to Use

- `file` reports a PE and the binary contains a CLR header or `mscoree.dll`
- ILSpy or dnSpy opens the assembly but names are mangled or bodies are empty
- Analyzing .NET malware, loaders, or red-team tooling
- Reviewing a Windows desktop or service application without source
- Recovering logic from a PowerShell or C# in-memory loader

## When NOT to Use

- **Unity IL2CPP** — use `reversing-unity-il2cpp`; the C# is compiled to native
- **Xamarin/MAUI mobile** — use `reversing-xamarin-maui` for the container
  extraction, then come back here for the DLLs
- **Suspected malware, before containment** — use `analyzing-malware` first
- **Go or Rust binaries** — use the matching skill

## Confirm It Is Managed

```bash
# Linux
file target.exe                                 # "Mono/.Net assembly"
rg -a -o 'BSJB|mscoree\.dll|System\.Private\.CoreLib' target.exe | head

# Windows
dotnet-tool: ildasm /text target.exe | head
# CLR header presence in the optional header data directory 14 is the real test
```

| What you find | Publish mode | Approach |
| --- | --- | --- |
| Managed PE, references `mscorlib`/`System.Private.CoreLib` | Framework-dependent | Decompile directly |
| Native PE containing an embedded managed bundle | Single-file publish | Extract the bundle first |
| Native PE, no IL metadata at all | NativeAOT | Not .NET RE — use `analyzing-binaries` |
| `.dll` with no entry point | Library | Decompile; find callers elsewhere |

```bash
# Single-file publish: the managed assemblies are appended as a bundle
# Extract with a bundle extractor, or carve on the manifest header
ilspycmd --list-bundle target.exe 2>/dev/null || binwalk -Me target.exe
```

## Decompile

```bash
ilspycmd target.dll -o ./decompiled -p       # -p writes a project structure
# GUI: dnSpyEx (maintained fork), ILSpy, dotPeek
# dnSpyEx also debugs and edits assemblies, which is why it is the default choice

rg -n 'https?://|ConnectionString|ApiKey|password|Convert\.FromBase64String' ./decompiled | head -40
```

Read in this order: the entry point, then any type named for the product, then
anything referencing networking, crypto, or process APIs. Skip generated types
(`<>c__DisplayClass`, `<Module>`) unless following a specific closure.

## Identify the Obfuscator Before Fighting It

Deobfuscation is cheap when you name the tool and expensive when you do not.

```bash
detect-it-easy target.exe          # or DIE's CLI: diec
# Look for: ConfuserEx, .NET Reactor, SmartAssembly, Eazfuscator, Babel,
#           Dotfuscator, Agile.NET, Obfuscar
rg -a -o 'ConfuserEx|Reactor|SmartAssembly|Eazfuscator|Babel|DotNetPatcher' target.exe
```

```bash
# de4dot handles the classic obfuscators automatically
de4dot target.exe -o cleaned.exe
de4dot -p cr target.exe            # force a specific profile when detection fails
# ConfuserEx specifically: use a maintained unpacker fork, since de4dot's
# built-in support predates later ConfuserEx versions
```

What each obfuscation layer looks like, and how to handle it:

| Layer | Appearance | Handling |
| --- | --- | --- |
| Name mangling | `Class1.method_3`, unicode/invisible names | Cosmetic — rename as you read; de4dot restores some |
| String encryption | `<Module>.Decrypt(12345)` everywhere | Run the decryptor: de4dot, or invoke the method dynamically |
| Control flow flattening | Giant `switch` on a state variable | de4dot's CFG cleanup, or read dynamically |
| Proxy/delegate calls | Every call goes through a helper | de4dot devirtualization |
| Anti-tamper / anti-debug | Fails under dnSpy debugger | Patch the check, or dump after decryption |
| Virtualization (Agile.NET, KoiVM) | No recognizable IL at all | Devirtualizer (`OldRod` for KoiVM) or dynamic analysis |
| Native stub wrapping IL | Managed code decrypted at runtime | **Dump from memory** — the reliable answer |

**Dumping from memory is the general escape hatch.** Whatever the packer, the
CLR must eventually hold real IL to execute it. Let it load, then dump:

```bash
# MegaDumper / ExtremeDumper / pe-sieve — dump loaded managed modules from a
# running process, then decompile the dump
pe-sieve /pid <pid> /dmode 3
```

This is the same "let it unpack itself" pattern as packed native malware; see
`analyzing-malware` for containment before running anything hostile.

## Debugging and Patching

```bash
# dnSpyEx: set breakpoints in decompiled C#, inspect locals, edit method bodies,
# and save the modified assembly. This is unusually powerful — you can change a
# license check or a validation result and immediately re-run.
```

Patching workflow: edit the IL or the decompiled C# in dnSpyEx, save the
assembly, and re-run. Strong-name signatures break on save — either remove the
strong name requirement, or if the app verifies its own hash, hook the check.
For a signed assembly the app itself verifies, patching is usually the wrong
tool; hook at runtime instead.

## .NET Malware Notes

.NET is heavily used for loaders and commodity RATs, and the artifacts are
distinctive:

- **`Assembly.Load(byte[])`** — a second stage decrypted in memory. Find the
  decryption routine, run it offline, and analyze the resulting assembly. This
  is the single most common .NET malware pattern.
- **`Activator.CreateInstance` plus reflection** to hide the real call graph.
- **`AmsiScanBuffer` / `EtwEventWrite` patching** — search for the byte
  patterns or the `GetProcAddress` calls that precede them.
- **P/Invoke declarations** (`[DllImport]`) reveal native capability:
  `VirtualAlloc`, `CreateRemoteThread`, `SetWindowsHookEx`.
- **Resources and satellite assemblies** holding encrypted payloads — always
  enumerate the resource section.

```bash
rg -n 'DllImport|Assembly\.Load|CreateInstance|FromBase64String|RijndaelManaged|AmsiScanBuffer' ./decompiled | head -30
ilspycmd --list-resources target.dll
```

Extracted second stages go back through this skill; capability and IOC output
goes to `analyzing-malware`, detection content to `engineering-detections`.

## Rationalizations to Reject

- *"The names are meaningless, it's too obfuscated."* Name mangling is the
  weakest layer. The structure, strings, and P/Invokes are intact.
- *"de4dot failed, so it can't be deobfuscated."* Identify the obfuscator and
  use its specific unpacker, or dump from memory.
- *"It's a native EXE, so it isn't .NET."* Check for single-file publish and
  for native stubs wrapping managed code.
- *"The strings are encrypted."* The decryptor is in the assembly. Call it.
- *"I decompiled the loader, that's the malware."* The loader is stage one.
  Find the `Assembly.Load` and recover what it loads.
- *"I'll read the flattened control flow manually."* Run the cleanup, or debug
  it in dnSpyEx and watch the real path.

## References

- `analyzing-malware` — containment, capability model, and IOCs
- `analyzing-binaries` — NativeAOT and native stub analysis
- `reversing-unity-il2cpp`, `reversing-xamarin-maui` — the other .NET containers
- `engineering-detections` — turning recovered behaviour into rules
- dnSpyEx, ILSpy/ilspycmd, de4dot, Detect It Easy, pe-sieve, OldRod
