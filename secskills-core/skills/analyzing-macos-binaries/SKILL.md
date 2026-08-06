---
name: analyzing-macos-binaries
description: Reverse engineer and security-review macOS applications and Mach-O binaries — thinning universal binaries, recovering Objective-C/Swift structure, reading code-signing entitlements and the hardened runtime, and auditing XPC services, dylib load paths, and TCC privacy exposure. Use when analyzing a .app bundle or Mach-O on macOS, checking entitlements and notarization, hunting a dylib-hijack or XPC privilege bug, or reasoning about Gatekeeper and quarantine.
verified: 2026-08-07
---

# Analyzing macOS Binaries

macOS reverse engineering is Mach-O plus a specific security model: code
signing, entitlements, the sandbox, TCC privacy, and XPC between processes. The
binary tells you what the code does; the entitlements and load paths tell you
what it is *allowed* to do and where an attacker could get in. Read both — most
macOS findings live in the gap between the two.

## When to Use

- Analyzing a `.app` bundle or a Mach-O executable/dylib/framework on macOS
- Reading entitlements, hardened-runtime flags, notarization, and Gatekeeper
  quarantine state
- Auditing an XPC service or privileged helper for an authorization bug
- Hunting dylib hijacking / proxying via `@rpath` and weak dylibs
- Reasoning about TCC privacy exposure and sandbox escape surface

## When NOT to Use

- **iOS apps** — IPA decryption, FairPlay (`cryptid=1`), App Store binaries —
  are `analyzing-ios-binaries`. Same Mach-O format, different toolchain and DRM.
- **Non-Mach-O or cross-platform triage** with no macOS specifics —
  `analyzing-binaries`.
- **Turning a memory-corruption crash into an exploit** —
  `exploiting-memory-corruption`.
- **A Mach-O that is packed/encrypted before you can read it** —
  `unpacking-protected-binaries`.

## Triage the Binary and Bundle

- **Thin the universal binary.** macOS ships fat binaries (x86_64 + arm64); use
  `lipo -thin` (or `lipo -archs` to list) so your tools work on one slice.
- **Read the Mach-O.** `otool -l` for load commands, `otool -L` for linked
  dylibs and their paths, `nm` for symbols. Note the load commands that matter
  later: `LC_RPATH`, `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB`, and the code
  signature.
- **Walk the bundle.** `Contents/MacOS` (the binary), `Info.plist` (identifiers,
  URL schemes), `_CodeSignature`, embedded `Frameworks/`, and any bundled
  `XPCServices/`. The bundle layout is the map of what to analyze.

## Recover Objective-C and Swift

- **Objective-C** keeps rich runtime metadata: `class-dump` (or `dsdump`)
  reconstructs class, method, and property declarations straight from the
  binary. This is the fastest way to see the app's structure.
- **Swift** is harder — names are mangled and metadata is less forthcoming. Run
  `swift-demangle` over symbols to get readable names, and expect to lean on the
  decompiler (Hopper, Ghidra, IDA) more than with Objective-C.
- Note which language dominates before choosing the approach; a Swift binary
  where `class-dump` returns little is normal, not a failure.

## Code Signing, Entitlements, and Gatekeeper

This is where macOS-specific authority lives:

- **`codesign -dvvv --entitlements :- <binary>`** dumps the signature and the
  **entitlements** — the capabilities the OS grants. Entitlements like
  `com.apple.security.get-task-allow` (debuggable), disabled library validation,
  or private TCC entitlements are the high-value reads.
- **Hardened runtime** flags restrict code injection and debugging; note whether
  they are on, and whether library validation is disabled (which allows loading
  unsigned dylibs — directly relevant to hijacking).
- **Notarization and Gatekeeper.** Downloaded files carry the
  `com.apple.quarantine` extended attribute; Gatekeeper checks notarization on
  first run. Understand the quarantine/notarization state when reasoning about
  what will execute and what a user was warned about.

## The macOS-Specific Bug Surface

- **Dylib hijacking / proxying.** A binary that loads a dylib from an `@rpath`
  that resolves to a writable location, or a `LC_LOAD_WEAK_DYLIB` that is absent,
  lets an attacker drop a malicious dylib and get code execution in the app's
  context — inheriting its entitlements. Enumerate the load paths and check which
  are attacker-writable and unprotected by library validation.
- **XPC services and privileged helpers.** XPC is the mach-based IPC between an
  app and its helpers (often a `SMJobBless` root helper). The classic bug is a
  helper that authorizes a client by **PID** — which races and is spoofable —
  instead of by **`audit_token`**. Trace how the service validates its caller and
  what privileged action it will perform; weak validation is local privilege
  escalation.
- **TCC privacy.** TCC gates access to camera, mic, files, and automation. Look
  at what the app is entitled to and whether it can be coerced into acting as a
  confused deputy for a less-privileged process, or whether an injectable
  dylib inherits its TCC grants.
- **URL schemes and `Info.plist` handlers** register the app to handle input
  from other apps and the web — an untrusted-input entry point.

## Dynamic Analysis

Frida attaches to macOS processes for runtime hooking; `lldb` debugs (subject to
`get-task-allow`/SIP); `dtrace` traces syscalls and library calls where SIP
permits. Use these to watch XPC messages and dylib loads live rather than
inferring them from the binary alone.

## Rationalizations to Reject

- **"It's signed and notarized, so it's safe."** Signing proves origin, not
  safety, and says nothing about a dylib-hijack path or an XPC helper that
  trusts its caller's PID. Read the entitlements and load paths.
- **"class-dump returned almost nothing, the binary is stripped."** That is the
  normal signature of a Swift binary. Switch to `swift-demangle` and the
  decompiler rather than concluding there is nothing to see.
- **"The helper checks the client PID, that's authentication."** PID checks race
  and are spoofable. Only `audit_token`-based validation is sound; a PID check is
  the finding.
- **"Library validation will stop a malicious dylib."** Only if it is enabled.
  Check for the disable-library-validation entitlement and hardened-runtime state
  before assuming the load is protected.
- **"This is just the iOS process on a Mac."** The DRM, toolchain, and security
  model differ. Use `analyzing-ios-binaries` for FairPlay IPAs; this skill for
  the macOS app and its XPC/TCC/dylib surface.

## References

- `analyzing-ios-binaries` — iOS IPAs, FairPlay, and mobile toolchain
- `analyzing-binaries` — general Mach-O triage and decompilation technique
- `exploiting-memory-corruption` — exploiting a native bug found here
- `unpacking-protected-binaries` — when the Mach-O is packed/encrypted first
