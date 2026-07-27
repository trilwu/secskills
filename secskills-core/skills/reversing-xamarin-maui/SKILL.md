---
name: reversing-xamarin-maui
description: Reverse engineer Xamarin and .NET MAUI mobile apps by extracting assemblies.blob and XALZ-compressed DLLs with pyxamstore, then decompiling with dnSpy or ILSpy. Use when an APK contains libmonodroid.so, libmonosgen, assemblies.blob, assemblies/*.dll, or libxamarin-app.so, when an IPA contains Mono assemblies, or when jadx shows only Xamarin bootstrap classes.
verified: 2026-07-27
---

# Reversing Xamarin and .NET MAUI Apps

Xamarin apps hide a complete .NET application inside an Android package. Once
you extract and decompress the assemblies you get near-source-quality C#, which
makes this one of the highest-return reversing jobs — but only if you get past
the container format, which changed twice and defeats naive unzipping.

## When to Use

- The APK contains `lib/*/libmonodroid.so`, `libmonosgen-2.0.so`, or
  `libxamarin-app.so`
- The APK contains `assemblies/assemblies.blob` or `assemblies/*.dll`
- `jadx` shows only `mono.MonoPackageManager` and Xamarin bootstrap classes
- An IPA contains `.dll` files or a `Frameworks/Mono*` layout
- The target is described as Xamarin, Xamarin.Forms, or .NET MAUI

## When NOT to Use

- **Unity** (`global-metadata.dat`, `libil2cpp.so`) — use `reversing-unity-il2cpp`;
  Unity is also .NET but uses a completely different packaging
- **Flutter or React Native** — use `reversing-flutter-apps` or
  `reversing-react-native-apps`
- **TLS interception problems** — use `bypassing-mobile-pinning`
- **The wider assessment** — use `testing-mobile-applications`

## Identify the Packaging Generation

Three formats shipped over the product's life, and the extraction differs.

```bash
unzip -l target.apk | rg 'assemblies|libmonodroid|libxamarin|libmonosgen'
```

| What you see | Generation | Extraction |
| --- | --- | --- |
| `assemblies/*.dll`, readable PE headers (`MZ`) | Classic, uncompressed | Unzip and decompile directly |
| `assemblies/*.dll` starting with `XALZ` | Classic, LZ4-compressed | Decompress the XALZ wrapper first |
| `assemblies/assemblies.blob` + `.manifest` | AssemblyStore | `pyxamstore` to unpack |
| `lib/*/libxamarin-app.so` with no `assemblies/` | .NET 6+ / MAUI, assemblies in the ELF | Extract from the shared library |
| No managed assemblies anywhere | NativeAOT | Not .NET reversing — use `analyzing-binaries` |

```bash
# Which one is it? Check the first four bytes of an assembly
unzip -p target.apk 'assemblies/Mono.Android.dll' 2>/dev/null | xxd | head -1
# 4d5a...  → MZ, a plain .NET PE, decompile now
# 58414c5a → "XALZ", LZ4-compressed, decompress first
```

## Extraction

```bash
# AssemblyStore (assemblies.blob)
pyxamstore unpack -d ./out target.apk
# produces the individual .dll files under ./out

# XALZ-compressed individual DLLs
# The header is: magic "XALZ" | descriptor index | uncompressed size | LZ4 block
python3 -c "
import lz4.block, struct, sys
d = open(sys.argv[1],'rb').read()
assert d[:4] == b'XALZ'
size = struct.unpack('<I', d[8:12])[0]
open(sys.argv[2],'wb').write(lz4.block.decompress(d[12:], uncompressed_size=size))
" Mono.Android.dll Mono.Android.decompressed.dll

# MAUI / .NET 6+ assemblies embedded in libxamarin-app.so
# They are stored as sections; carve by MZ header or use pyxamstore's newer modes
unzip -j target.apk 'lib/arm64-v8a/*' -d libs && binwalk -Me libs/libxamarin-app.so
```

Once you have plain `.dll` files it is ordinary .NET work:

```bash
ilspycmd ./out/YourApp.dll -o ./decompiled     # or dnSpy / dnSpyEx / dotPeek
rg -n 'https?://|ApiKey|ConnectionString|Bearer|password' ./decompiled | head -40
```

**Start with the app's own assembly**, not the framework ones. It is usually
named after the product; `Mono.Android.dll`, `System.*`, and `Xamarin.*` are
stock and waste your time.

## Runtime Hooking

Frida's Java bridge does not see Mono methods — the app's logic is not in the
JVM. You need Mono-aware instrumentation.

```bash
# Enumerate the Mono runtime and its loaded assemblies
frida -U -f com.target.app -l frida-mono-api.js
# Fridax targets Xamarin specifically; also useful:
#   mono_get_root_domain, mono_assembly_foreach, mono_class_get_methods,
#   mono_compile_method  → resolve a managed method to a native address, then
#   Interceptor.attach at that address
```

The practical route: decompile first, find the exact class and method you want,
then resolve it through the Mono API and attach. Blind hooking of Mono is far
slower than reading the C# you already recovered.

**Certificate validation in Xamarin lives in managed code**, which is why
generic Android pinning bypasses miss it entirely:

```csharp
// The two hook targets, both in the managed layer
ServicePointManager.ServerCertificateValidationCallback
HttpClientHandler.ServerCertificateCustomValidationCallback
```

Force these to return `true` via Mono hooking, or patch the assembly and
repack. See `bypassing-mobile-pinning` for the surrounding diagnosis.

## Where the Findings Are

Xamarin apps concentrate risk in ways that are easy to spot once decompiled:

- **Hardcoded secrets in C#.** Developers treat compiled assemblies as opaque;
  API keys, connection strings, and storage credentials ship in plain IL.
- **Full backend logic in the client.** Shared code between the mobile app and
  the server-side project is a Xamarin idiom, so the client often contains the
  authoritative business rules — and sometimes the server's own models and
  validation, which tells you exactly how to shape a malicious request.
- **Custom `ServerCertificateValidationCallback` returning `true`.** Common in
  development builds that shipped.
- **Insecure local storage.** `Xamarin.Essentials.SecureStorage` is usually
  fine; `Preferences` and raw file writes are not.
- **Embedded SQLite** with credentials or full offline datasets.

## Patching and Repacking

```bash
# Edit IL directly in dnSpy, save the assembly, then rebuild the container
pyxamstore pack -d ./out          # rebuild assemblies.blob
apktool b target -o patched.apk && apksigner sign --ks debug.keystore patched.apk
```

Repacking must reproduce the original container format exactly — an
uncompressed DLL where the loader expects XALZ, or a mis-sized blob, fails at
startup with an unhelpful native crash. Prefer runtime hooking when you only
need to observe.

## Rationalizations to Reject

- *"jadx found nothing, so it's obfuscated."* There is nothing in the dex. The
  app is in `assemblies/`.
- *"Unzipping gave me DLLs but dnSpy rejects them."* They are XALZ-compressed.
  Check the first four bytes.
- *"Frida's Java hooks aren't working."* The methods are Mono, not JVM. Use the
  Mono API.
- *"It's compiled to a DLL, so the key is safe."* IL decompiles to readable C#.
  Treat every assembly constant as public.
- *"The pinning bypass ran and traffic still fails."* Xamarin validates in
  managed code; the Java-layer bypass never touched it.
- *"There are hundreds of assemblies."* Most are stock framework. Read the one
  named after the product.

## References

- `testing-mobile-applications` — the wider assessment and platform storage
- `bypassing-mobile-pinning` — diagnosing the interception failure around this
- `reversing-unity-il2cpp` — the other .NET-based mobile framework
- `analyzing-binaries` — NativeAOT builds with no managed assemblies
- pyxamstore, dnSpy/dnSpyEx, ILSpy, Fridax, frida-mono-api
