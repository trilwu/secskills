---
name: reversing-react-native-apps
description: Reverse engineer React Native mobile apps, including Hermes bytecode bundles, using hbctool, hermes-dec, and Frida. Use when an APK contains index.android.bundle or libhermes.so, when an IPA contains main.jsbundle, when jadx shows only ReactActivity classes, or when a bundle file starts with the Hermes magic bytes instead of readable JavaScript.
verified: 2026-07-27
---

# Reversing React Native Apps

React Native apps are JavaScript wearing a native shell. That is good news —
the application logic ships as a bundle you can read — unless the bundle was
compiled to Hermes bytecode, in which case you need a decompiler and the
version compatibility problem becomes the whole task.

## When to Use

- `jadx` shows `ReactActivity`, `ReactNativeHost`, and little application logic
- The APK contains `assets/index.android.bundle` or `lib/*/libhermes.so`
- The IPA contains `main.jsbundle`
- You need to find API endpoints, secrets, or business logic in an RN app
- You need to patch or hook JavaScript-level behaviour

## When NOT to Use

- **Flutter** (`libapp.so`, `libflutter.so`) — use `reversing-flutter-apps`
- **Unity** (`global-metadata.dat`) — use `reversing-unity-il2cpp`
- **Native Java/Kotlin apps** — use `testing-mobile-applications`
- **Native modules written in C/C++** — use `analyzing-binaries`

## Identify the Bundle Format

This one check decides whether the job takes ten minutes or a day.

```bash
unzip -j target.apk 'assets/index.android.bundle' -d ./out
file ./out/index.android.bundle
xxd ./out/index.android.bundle | head -2
```

| First bytes | Format | Path |
| --- | --- | --- |
| Readable JS (`var __BUNDLE_START`, `__d(function`) | Plain JavaScript | Beautify and read directly |
| Binary, Hermes magic (`c6 1f bc 03` little-endian) | Hermes bytecode | Decompile — see below |

```bash
# Plain bundle: beautify, then it reads like any minified web app
npx js-beautify index.android.bundle -o bundle.js
rg -n 'https?://|api[_-]?key|Bearer |secret|token' bundle.js | head -50
```

A plain bundle is a gift. Module boundaries survive as `__d(function(...)`
registrations, source maps are occasionally shipped by mistake
(`index.android.bundle.map` — always check), and the whole application logic
is in front of you.

## Hermes Bytecode

Hermes compiles JS to its own bytecode (HBC). The bytecode version is embedded
in the header and **changes with React Native releases**, which is the single
biggest practical obstacle: a tool that supports HBC 74 will refuse or
misparse HBC 96.

```bash
# Read the version out of the header before choosing a tool
hbctool disasm index.android.bundle ./disasm     # HBC 59, 62, 74 ONLY
hermes-dec ...                                    # decompiler; wider version support
```

Upstream `hbctool` ships support for exactly three bytecode versions — **59,
62, and 74**. Anything else fails at parse. Check the header version first
rather than reading a parse error as "the bundle is protected"; on a current
React Native release you will usually be above 74 and should reach for
`hermes-dec` or a `hermesc` you built from the matching Hermes tag.

| Tool | Gives you | Caveat |
| --- | --- | --- |
| `hbctool` | Disassembly *and* reassembly — you can patch and repack | Supports a limited set of HBC versions |
| `hermes-dec` | Decompiled pseudo-JavaScript | Read-only; output is approximate |
| `hasmer` | Disassembly/assembly, alternate version coverage | Try when `hbctool` refuses the version |

When every tool rejects the version, the reliable fallback is to build the
matching `hermesc` from the React Native release the app used, and use its
tooling. That is slower but version-correct.

**What to do with the output.** Even imperfect decompilation is enough for the
questions that matter: string tables survive intact, so endpoints, keys, and
feature flags are recoverable directly:

```bash
strings -n 6 index.android.bundle | rg -i 'https?://|api|token|secret|firebase' | sort -u
```

The Hermes string table is a flat, readable region of the file. Reach for it
before decompiling — it often answers the question outright.

## Runtime Analysis

Frida is frequently faster than static work on RN, because the interesting
boundary is where JavaScript calls into native.

```bash
# Enumerate the native modules the JS side can reach
frida -U -f com.target.app -l rn-enumerate-modules.js

# Hook the bridge: every JS↔native call, with arguments
# (target the ReactNative bridge / TurboModule dispatch)
objection -g com.target.app explore
```

Useful hook points: `fetch`/`XMLHttpRequest` in the JS runtime, the native
networking module (OkHttp on Android — hookable with standard pinning bypass),
`AsyncStorage` reads and writes, and any `NativeModules.*` the app defines.

TLS interception is ordinary here — unlike Flutter, RN uses the platform HTTP
stack, so the usual system-CA plus proxy setup works, and standard pinning
bypasses apply. If interception fails, suspect pinning in a native module, not
a separate trust store.

## Where the Findings Usually Are

React Native apps concentrate the same few problems:

- **Secrets in the bundle.** API keys, Firebase configs, and third-party
  tokens shipped in JS because "it's compiled." Hermes is not encryption.
- **Client-side authorization.** Role checks and feature gates implemented in
  JS, trivially patched or simply ignored by calling the API directly.
- **`AsyncStorage` as a credential store.** Unencrypted by default; tokens and
  PII routinely land there.
- **Over-broad native modules.** Custom bridge methods that expose file system
  or shell access to JS, reachable from any injected script.
- **Debug artifacts.** Source maps, dev-mode bundles, and `console.log` output
  left in release builds.

## Patching and Repacking

```bash
hbctool disasm index.android.bundle ./work
# edit ./work/instruction.hasm and ./work/metadata.json
hbctool asm ./work index.android.bundle.patched
# replace in the APK, then re-sign
apktool b target -o patched.apk && apksigner sign --ks debug.keystore patched.apk
```

Patch only what you must, and only with authorization. Repacking trips
integrity checks in hardened apps; if the app validates its own bundle, hook
the check rather than defeating it by editing.

## Rationalizations to Reject

- *"The bundle is binary, so the logic is protected."* Hermes is a compiler,
  not a protection. The string table alone often gives up the API.
- *"jadx found nothing, so it's obfuscated."* There is nothing in the dex.
  Look in `assets/`.
- *"No tool supports this HBC version, dead end."* Build `hermesc` from the
  matching React Native release, or read the string table.
- *"The key is only used client-side."* It is in the bundle, so it is public.
  Treat every bundle secret as disclosed.
- *"The app enforces the role check."* The app is the client. Verify the check
  server-side by calling the API without it.

## References

- `testing-mobile-applications` — the wider assessment, storage, and platform issues
- `testing-apis` — the backend, which is where the real findings are
- `reversing-flutter-apps` — the other common cross-platform framework
- hbctool, hermes-dec, hasmer, Frida/objection, jadx, apktool
