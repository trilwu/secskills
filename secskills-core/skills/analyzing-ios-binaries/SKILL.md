---
name: analyzing-ios-binaries
description: Analyze iOS applications at the binary level — decrypting FairPlay-protected IPAs with frida-ios-dump or bagbak, inspecting Mach-O load commands, recovering Objective-C headers with class-dump, and reading Swift metadata. Use when working with an IPA or .app bundle, when a downloaded App Store binary shows cryptid=1, when class-dump returns nothing, or when analyzing iOS frameworks and app extensions.
verified: 2026-07-27
---

# Analyzing iOS Binaries

App Store binaries are encrypted at rest and decrypted by the kernel at load
time, so every static tool fails on a downloaded IPA until you dump the
decrypted image from memory. That single step gates everything else, and it is
the reason most iOS analysis stalls before it starts.

## When to Use

- You have an IPA or `.app` bundle and need to read the binary
- `class-dump` returns nothing or garbage
- `otool` shows `cryptid 1`
- You need to enumerate Objective-C classes, Swift types, or exported symbols
- Analyzing embedded frameworks, app extensions, or dynamic libraries

## When NOT to Use

- **Android targets** — use `testing-mobile-applications` or the relevant
  `reversing-*` skill
- **The wider iOS assessment** (storage, keychain, IPC) — use
  `testing-mobile-applications`
- **TLS interception** — use `bypassing-mobile-pinning`
- **Jailbreak detection blocking your tooling** — use
  `bypassing-root-jailbreak-detection` first
- **Cross-platform frameworks** — Flutter, Unity, and Xamarin have their own
  skills; use them for the managed layer and this one for the native shell

## Check Encryption First

```bash
otool -l TargetApp | grep -A5 LC_ENCRYPTION_INFO
# cryptid 1  → FairPlay-encrypted, decrypt before anything else
# cryptid 0  → already decrypted (dev build, or you already dumped it)
```

Everything downstream is meaningless on an encrypted binary. `class-dump`
returning nothing is almost always this, not obfuscation.

```bash
# Decrypt on a jailbroken device by dumping the loaded image
frida-ios-dump -l                 # list installed apps
frida-ios-dump com.target.app     # produces a decrypted IPA
bagbak com.target.app             # alternative, handles extensions/frameworks well

# Rootless jailbreaks and TrollStore installs work with the same tools
# Older devices: Clutch, flexdecrypt
```

Dump **frameworks and extensions too**, not just the main binary. `PlugIns/`
(share sheets, widgets, keyboards) and `Frameworks/` carry their own encrypted
Mach-Os, and app extensions frequently hold the interesting entitlements and a
weaker security posture than the main app.

## Mach-O Structure and Protections

```bash
file TargetApp                       # thin or fat/universal
lipo -info TargetApp                 # architectures present
lipo -thin arm64 TargetApp -o app64  # extract one before analysis

otool -hv app64                      # header flags: PIE
otool -l app64 | rg 'LC_LOAD_DYLIB|LC_RPATH|LC_CODE_SIGNATURE|LC_ENCRYPTION'
otool -Iv app64 | head               # indirect symbols
nm -m app64 | rg -v ' U ' | head     # defined symbols

# Protections at a glance
otool -hv app64 | rg PIE             # ASLR
otool -Iv app64 | rg stack_chk       # stack canaries
otool -Iv app64 | rg objc_release    # ARC in use
```

Extract the entitlements — they define what the app is allowed to do and often
reveal the interesting attack surface:

```bash
codesign -d --entitlements :- TargetApp.app
# Look for: keychain-access-groups, App Groups, associated-domains,
# get-task-allow (debuggable!), custom URL scheme claims
```

`get-task-allow` set to true on a production build means the app is debuggable
and is a finding on its own.

## Objective-C

Objective-C keeps its full class metadata in the binary, so recovery is
excellent — method names, selectors, class hierarchy, ivars.

```bash
class-dump -H app64 -o ./headers        # classic
class-dump-dyld                          # for dyld shared cache resident classes
dsdump --objc --color app64              # modern alternative, handles Swift too

# Then read the type map
rg -l 'Manager|Service|API|Auth|Crypto|Keychain|Payment' ./headers | head -20
```

In a disassembler, Objective-C calls go through `objc_msgSend`, so the callee
is a selector string in a register rather than a direct branch. Both IDA and
Ghidra have plugins that resolve this; without them the call graph is largely
useless.

## Swift

Swift is harder. Names are mangled, and method dispatch is often static or
through witness tables rather than `objc_msgSend`.

```bash
# Demangle what you find
nm app64 | swift demangle
xcrun swift-demangle '$s10TargetApp11AuthManagerC5loginyyF'

# Swift type metadata lives in dedicated sections
otool -l app64 | rg '__swift5_types|__swift5_proto|__swift5_reflstr'
dsdump --swift app64
```

Practical approach for Swift-heavy apps: `@objc` and `@objcMembers` members
still appear in the Objective-C metadata, so class-dump gives you a partial
map. For the rest, work from string references and the reflection sections
rather than trying to recover a full class list. Runtime enumeration with
Frida is usually faster than static recovery:

```bash
frida -U -f com.target.app -l enumerate-swift-classes.js
```

## Runtime Analysis

```bash
# Enumerate everything the runtime knows
objection -g com.target.app explore
#   ios hooking list classes
#   ios hooking search methods <keyword>
#   ios hooking watch method "-[AuthManager login:]" --dump-args --dump-return

# Direct Frida for anything objection does not cover
frida -U -f com.target.app -l hooks.js
```

Runtime beats static on iOS more often than on other platforms: the
Objective-C runtime is introspectable, so listing classes and watching methods
gets you to the logic faster than reading a disassembly of `objc_msgSend`
dispatch.

## What to Look For

- **Entitlements over-provisioned** — App Groups shared with less-trusted
  extensions, keychain groups shared too widely, `get-task-allow` in production
- **Hardcoded secrets** in `__cstring` and in the plist files inside the bundle
- **Weak keychain accessibility** — items stored with
  `kSecAttrAccessibleAlways` rather than a `ThisDeviceOnly` class
- **Custom crypto** in the binary rather than CryptoKit/CommonCrypto
- **Debug and logging code** left in release builds
- **Insecure `WKWebView` configuration** — `allowFileAccessFromFileURLs`,
  loading remote content into a JS-bridged view
- **Third-party SDKs** with their own network stacks and their own pinning
  behaviour; enumerate `Frameworks/` and check each

## Rationalizations to Reject

- *"class-dump returned nothing, the app is obfuscated."* Check `cryptid`
  first. It is almost always encryption.
- *"I dumped the main binary, that's the app."* Extensions and frameworks are
  separate Mach-Os with separate entitlements, and are frequently weaker.
- *"It's Swift, so nothing is recoverable."* Reflection sections, `@objc`
  members, and string references recover a great deal. Enumerate at runtime.
- *"Static analysis is enough."* On iOS the runtime is introspectable; skipping
  it costs more than it saves.
- *"The binary has PIE and canaries, so it's hardened."* Those are compiler
  defaults, not evidence of a security review.
- *"I can't jailbreak, so I can't analyze."* You can still read the bundle,
  plists, entitlements, and assets, and repackage with a Frida gadget for
  sideloading. Say what the constraint cost you in the report.

## References

- `testing-mobile-applications` — storage, keychain, IPC, and the wider iOS test
- `bypassing-root-jailbreak-detection` — when detection blocks your tooling
- `bypassing-mobile-pinning` — TLS interception on iOS stacks
- `analyzing-binaries` — deeper native RE of the same Mach-O
- frida-ios-dump, bagbak, class-dump, dsdump, objection, Hopper/IDA/Ghidra
