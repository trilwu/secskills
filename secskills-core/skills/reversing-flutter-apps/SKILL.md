---
name: reversing-flutter-apps
description: Reverse engineer and intercept traffic from Flutter/Dart mobile apps using blutter, reFlutter, and Frida. Use when an APK or IPA contains libflutter.so, libapp.so, App.framework, or flutter_assets, when jadx shows only a thin Dart wrapper, when Burp or mitmproxy sees no traffic from an app that is clearly online, or when the target is described as built with Flutter or Dart.
---

# Reversing Flutter Apps

Flutter breaks both halves of the standard mobile workflow at once. Dart is
AOT-compiled to a native snapshot, so there is no dex for jadx to decompile —
and the Flutter engine ships its own BoringSSL with its own trust store, so it
ignores the system proxy *and* the user CA store, and your interception proxy
sees nothing. Neither failure is obvious from the symptoms, which is why
people burn hours on this before recognizing what they are looking at.

## When to Use

- `jadx` on the APK shows a near-empty `MainActivity` and little else
- The APK contains `lib/arm64-v8a/libflutter.so` and `libapp.so`, or
  `assets/flutter_assets/`
- An IPA contains `Frameworks/App.framework` and `Frameworks/Flutter.framework`
- Burp, mitmproxy, or Charles shows zero traffic from an app that is plainly
  making network calls
- You need to recover Dart class and method names, or find the API layer, in a
  release build

## When NOT to Use

- **Ordinary Java/Kotlin Android apps** — use `testing-mobile-applications`
- **React Native** (`index.android.bundle`, Hermes) — use `reversing-react-native-apps`
- **Unity** (`global-metadata.dat`, `libil2cpp.so`) — use `reversing-unity-il2cpp`
- **The backend the app talks to** — use `testing-apis` once you can see traffic
- **Generic native `.so` reversing** — use `analyzing-binaries`

## Identify the Build First

The build mode decides everything that follows. Check before installing tools.

```bash
unzip -l target.apk | rg 'libflutter|libapp|flutter_assets|kernel_blob'
```

| What you see | Build | What it means |
| --- | --- | --- |
| `libapp.so` + `libflutter.so` | AOT release | The normal case. Dart compiled to a native snapshot — this skill's main path |
| `assets/flutter_assets/kernel_blob.bin` | Debug / JIT | Far easier: Dart kernel bytecode, and the VM service may be reachable |
| `App.framework/App` (iOS) | AOT release | Same as `libapp.so`; extract from the decrypted IPA |
| Only `arm64-v8a` present | — | Expected; blutter targets arm64. `armeabi-v7a` support is weaker |

```bash
# Confirm the engine version — it gates which tools work
strings lib/arm64-v8a/libflutter.so | rg -m5 'Flutter|Dart VM version|dart-sdk'
```

If `kernel_blob.bin` is present, stop and unpack that instead: debug builds
retain far more, and the Dart VM service (if enabled) gives you live
inspection. Release builds are the hard case, and the rest of this assumes one.

## Recovering Dart Structure with blutter

[blutter](https://github.com/worawit/blutter) parses the Dart AOT snapshot and
recovers class, method, and field names plus the object pool — the difference
between an unreadable arm64 listing and a navigable app.

```bash
# blutter needs BOTH libraries: libapp.so is the snapshot, libflutter.so
# identifies the exact Dart version used to compile it
unzip -j target.apk 'lib/arm64-v8a/*' -d ./libs
python3 blutter.py ./libs ./out
```

Output you will actually use:

| Artifact | Use |
| --- | --- |
| `pp.txt` | Object pool dump — string constants, URLs, keys, endpoints. **Read this first** |
| `objs.txt` | Recovered Dart objects and classes |
| `asm/` | Per-library disassembly with Dart symbols applied |
| `ida_script/` | Loads symbols into IDA; equivalents exist for Ghidra |
| `blutter_frida.js` | Generated Frida hooks against recovered Dart functions |

**The failure you will hit is a Dart version mismatch.** blutter compiles
against a specific Dart SDK, and the snapshot format changes between versions.
When it errors on parsing, the fix is to build blutter against the Dart SDK
version that matches the app's engine, not to try a different snapshot. Read
the version out of `libflutter.so` first, and expect the first run against a
brand-new Flutter release to fail until blutter catches up.

**Obfuscated builds** (`flutter build --obfuscate --split-debug-info=...`)
strip Dart names. blutter still recovers structure — call graph, object pool,
string constants — but the names are gone. Pivot to `pp.txt`: URLs, endpoint
paths, and error strings survive obfuscation and are usually enough to locate
the API layer, which is what you wanted anyway.

## Seeing the Traffic

Two separate problems, and both must be solved. Fixing only one leaves you
with an empty proxy and no idea why.

**Problem 1 — Flutter ignores the system proxy.** Dart's HTTP client does not
read Android/iOS proxy settings, so setting a Wi-Fi proxy does nothing. Force
traffic at the network layer instead:

```bash
# Redirect transparently on the device/emulator
adb shell su -c 'iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to <proxy-ip>:8080'
# or use a VPN-based tunnel (tun2socks / a VPN-mode proxy app)
```

**Problem 2 — Flutter has its own CA store.** Installing your CA as a user
certificate, or even as a system certificate, does not make Flutter trust it.
Two working approaches:

```bash
# A. reFlutter — patches the Flutter engine to trust your proxy and to
#    reroute traffic. Repackage and re-sign afterwards.
reflutter target.apk           # prompts for the proxy IP
# outputs a patched APK; then:
apksigner sign --ks debug.keystore release.RE.apk

# B. Frida — hook the certificate check inside libflutter.so at runtime.
#    ssl_verify_peer_cert is not exported, so scripts locate it by pattern
#    scanning; the pattern is engine-version specific.
frida -U -f com.target.app -l flutter-ssl-bypass.js
```

Prefer reFlutter when you can repackage (it also enables snapshot dumping and
socket-level logging); prefer Frida when the app has integrity checks that a
repackage would trip, or when you cannot re-sign. If both fail, the fallback
is to hook the Dart HTTP client functions that blutter recovered — you lose
protocol-level fidelity but still see requests and responses.

## Working the App

Once you have symbols and traffic:

1. **Start from `pp.txt`.** Base URLs, endpoint paths, header names, and any
   embedded key material are in the object pool. This usually maps the API in
   minutes.
2. **Hook recovered functions** using `blutter_frida.js` as a starting point —
   dump arguments and return values around the request builder, the auth token
   handler, and any local crypto.
3. **Check the platform channels.** Flutter apps delegate to native code for
   biometrics, keystore, and payments; those are ordinary Java/Kotlin or
   Swift, so hand them to `testing-mobile-applications`.
4. **Then test the API properly** with `testing-apis`. Everything above was to
   get you to the request; the vulnerabilities are usually on the other end.

## Rationalizations to Reject

- *"The proxy shows nothing, so the app must not use the network."* It uses
  the network. It is not using your proxy.
- *"I installed the CA as a system cert, so TLS interception will work."*
  Flutter does not consult the system store.
- *"jadx showed nothing, so the app is heavily obfuscated."* There is nothing
  in the dex to see. The app is in `libapp.so`.
- *"blutter failed, so this build can't be analyzed."* It almost always means
  a Dart version mismatch. Read the engine version and rebuild blutter against it.
- *"It's obfuscated, so the strings are gone."* Names are gone; the object
  pool is not. Read `pp.txt`.
- *"I'll just reverse the arm64 by hand."* Dart AOT output without symbols is
  extraordinarily slow to read. Recover symbols first — it is the whole job.

## References

- `testing-mobile-applications` — the wider mobile assessment and native channels
- `testing-apis` — testing the backend once traffic is visible
- `analyzing-binaries` — deeper native work on the engine itself
- blutter, reFlutter, Frida/objection, jadx, apktool, apksigner
