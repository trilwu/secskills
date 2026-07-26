---
name: reversing-unity-il2cpp
description: Reverse engineer Unity games and apps built with IL2CPP or Mono, using Il2CppDumper, Il2CppInspector, and dnSpy. Use when an APK or IPA contains global-metadata.dat, libil2cpp.so, UnityFramework, or Assembly-CSharp.dll, when jadx shows only UnityPlayerActivity, or when the target is described as a Unity build.
---

# Reversing Unity IL2CPP

Unity ships in two very different shapes, and identifying which one you have
is the entire first decision. A Mono build hands you decompilable .NET
assemblies. An IL2CPP build compiles C# to C++ to native code, and the C#
metadata lives in a separate file that you must recombine with the binary
before anything is readable.

## When to Use

- The APK contains `assets/bin/Data/Managed/Metadata/global-metadata.dat` and
  `lib/arm64-v8a/libil2cpp.so`
- The APK contains `assets/bin/Data/Managed/Assembly-CSharp.dll` (Mono build)
- The IPA contains `Frameworks/UnityFramework.framework`
- `jadx` shows only `UnityPlayerActivity` and Unity plumbing
- You need to recover game or app logic, anti-cheat behaviour, or the API layer

## When NOT to Use

- **Flutter or React Native** — use `reversing-flutter-apps` or
  `reversing-react-native-apps`
- **Ordinary native apps** — use `testing-mobile-applications`
- **Desktop game binaries with no Unity markers** — use `analyzing-binaries`
- **Building cheats or bypassing anti-cheat in live multiplayer services** —
  out of scope; that is service abuse, not assessment

## Identify the Build

```bash
unzip -l target.apk | rg 'global-metadata|libil2cpp|Assembly-CSharp|libmono'
```

| Present | Build | Difficulty |
| --- | --- | --- |
| `Assembly-CSharp.dll`, `libmono*.so` | Mono | Easy — decompile the DLL directly |
| `global-metadata.dat` + `libil2cpp.so` | IL2CPP | The main path below |
| Neither, but `UnityFramework` | iOS IL2CPP | Same as IL2CPP; extract from the decrypted IPA |

**Mono builds are a short job.** Pull the assembly and open it:

```bash
unzip -j target.apk 'assets/bin/Data/Managed/Assembly-CSharp.dll' -d ./out
# dnSpy / dnSpyEx / ILSpy / dotPeek — full C# source recovery, and dnSpy can edit
ilspycmd ./out/Assembly-CSharp.dll -o ./decompiled
```

Everything below is for IL2CPP.

## Recombining Metadata with the Binary

IL2CPP splits the information: `libil2cpp.so` holds the compiled code,
`global-metadata.dat` holds the C# type system — class names, method names,
field names, string literals. Neither is useful alone. The tools' job is to
match them and produce symbols.

```bash
unzip -j target.apk 'lib/arm64-v8a/libil2cpp.so' \
                    'assets/bin/Data/Managed/Metadata/global-metadata.dat' -d ./in

# Il2CppDumper: the standard first attempt
Il2CppDumper ./in/libil2cpp.so ./in/global-metadata.dat ./out
```

Typical output and what it is for:

| Artifact | Use |
| --- | --- |
| `dump.cs` | Every class, method, and field with addresses — **read this first** |
| `DummyDll/` | Stub .NET assemblies; open in dnSpy/ILSpy to browse the type system comfortably |
| `script.json` | Symbol import for IDA/Ghidra — applies names to `libil2cpp.so` |
| `stringliteral.json` | String constants: URLs, keys, messages |

`Il2CppInspector` is the alternative when Il2CppDumper fails; it supports a
different range of Unity versions and emits Ghidra and IDA scripts plus a
richer C++ header. Try both before concluding a build is unsupported.

**Version mismatch is the usual failure.** The metadata format changes across
Unity releases; the tool asks for or infers the version. Read the Unity
version first and feed it explicitly:

```bash
strings ./in/libil2cpp.so | rg -m3 '20[0-9]{2}\.[0-9]+\.[0-9]+' 
strings ./in/global-metadata.dat | head -5
```

**Protected builds** encrypt or scramble `global-metadata.dat` — the header
magic will be wrong and the dumpers will refuse. Signs: the file does not
start with the expected metadata magic, or entropy is uniformly high. The
practical route is dynamic: let the app decrypt the metadata itself, then dump
it from memory once loaded.

```bash
# Dump the decrypted metadata from a running process
frida -U -f com.target.app -l dump-metadata.js
# Then feed the dumped file to Il2CppDumper as normal
```

That pattern — let it unpack itself, dump from memory — is the same one used
for packed malware, and it is almost always cheaper than defeating the
protection statically. See `analyzing-binaries`.

## Working the Recovered Code

1. **Read `dump.cs` for the type map.** Search for the classes that matter:
   anything named `*Manager`, `*Service`, `*Api`, `*Network`, `*Auth`,
   `*Purchase`, `*Config`.
2. **Load `script.json` into IDA or Ghidra** so `libil2cpp.so` shows C# method
   names instead of `sub_1A2B3C`. Without this step the disassembly is
   unreadable; with it, it reads like decompiled C#.
3. **Check `stringliteral.json` for endpoints and keys.** Same reasoning as
   every other framework — string constants survive everything.
4. **Hook at runtime with Frida** using the addresses from `dump.cs`. Method
   addresses are relative to the `libil2cpp.so` base, so resolve the module
   base and add the offset.

```javascript
// Pattern: resolve base, add the RVA from dump.cs, intercept
const base = Module.findBaseAddress('libil2cpp.so');
Interceptor.attach(base.add(0x1A2B3C), {
  onEnter(args) { console.log('called with', args[1]); },
  onLeave(ret)  { console.log('->', ret); }
});
```

## Security-Relevant Findings

For an assessment rather than a curiosity exercise, the recurring issues:

- **Hardcoded credentials and endpoints** in `stringliteral.json` — backend
  keys, analytics tokens, cloud storage credentials.
- **Client-authoritative logic.** Currency, entitlements, and validation done
  in C# and trusted by the server. Verify by calling the API directly.
- **Weak or absent certificate pinning.** Unity's networking layer is often
  configured permissively; check `UnityWebRequest` usage.
- **Local save and config tampering.** `PlayerPrefs` and local save files
  storing values the server trusts.
- **Receipt validation done client-side** for in-app purchases.

## Rationalizations to Reject

- *"jadx shows nothing, so it's protected."* Unity apps have almost nothing in
  the dex by design.
- *"The dumper failed, so the build can't be analyzed."* Try the other dumper,
  supply the Unity version explicitly, and if metadata is encrypted, dump it
  from memory.
- *"IL2CPP is compiled, so the logic is safe."* The metadata ships alongside
  it. That is the whole point of the format.
- *"The client validates the purchase."* Then the purchase is not validated.
- *"I'll read the raw arm64."* Apply `script.json` first. The same function is
  unreadable before and routine after.

## References

- `testing-mobile-applications` — platform storage, permissions, and native layer
- `testing-apis` — the backend, where client-authoritative logic becomes a finding
- `analyzing-binaries` — memory dumping and anti-analysis for protected builds
- Il2CppDumper, Il2CppInspector, dnSpy/ILSpy, Frida, IDA/Ghidra
