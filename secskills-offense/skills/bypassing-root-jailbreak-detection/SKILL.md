---
name: bypassing-root-jailbreak-detection
description: Defeat root, jailbreak, emulator, debugger, and Frida detection in mobile apps using Magisk DenyList, Zygisk modules, objection, and targeted Frida hooks, and understand where hardware-backed attestation like Play Integrity cannot be hooked. Use when an app exits, shows "device not secure", or silently fails on a rooted device or emulator, or when Frida attaches and the app immediately dies.
---

# Bypassing Root and Jailbreak Detection

Detection is almost never one check. It is a dozen cheap checks scattered
across the app, plus — increasingly — one hardware-backed attestation that no
hook can touch. Hooking checks one at a time is whack-a-mole; the work is
finding the layer the app actually depends on.

Use only against apps you are authorized to test.

## When to Use

- The app exits on launch, shows "rooted device detected", or degrades silently
- The app works on a stock device but not on your test device or emulator
- Frida attaches and the process dies immediately, or `frida-ps` shows nothing
- `objection` fails to explore, or hooks stop firing after a few seconds
- You need a stable instrumentation environment before any other testing

## When NOT to Use

- **TLS interception failures** — use `bypassing-mobile-pinning`; a proxy error
  is a different problem, though detection can masquerade as one
- **The wider assessment** — use `testing-mobile-applications`
- **Framework-specific reversing** — use the relevant `reversing-*` skill
- **Defeating DRM or licensing to pirate an app** — out of scope

## Identify the Layer First

Detection lives at four layers, and each needs a different response. Working
out which one is firing saves the most time.

| Layer | Signals | Response |
| --- | --- | --- |
| **Java/managed checks** | `RootBeer`, `File.exists("/system/xbin/su")`, package queries for Magisk | Hook at the Java layer (objection, Frida) |
| **Native checks in `.so`** | `stat`/`access`/`fopen` on `su`, `/proc/self/maps` scans | Hook libc, or patch the `.so` |
| **Instrumentation detection** | Dies only when Frida is attached; port 27042 probes; thread-name scans | Hide the agent, not the root |
| **Hardware attestation** | Play Integrity, SafetyNet, DeviceCheck, App Attest | Cannot be hooked — see below |

```bash
# What does the app reference? Decompile and look before hooking.
apktool d target.apk -o out
rg -n 'RootBeer|isRooted|su\b|magisk|superuser|test-keys|/system/xbin|busybox|xposed|frida' -i out/smali* out/res 2>/dev/null | head -30
rg -n 'SafetyNet|PlayIntegrity|IntegrityManager|attest|DeviceCheck' -i out/ | head

# Native side
unzip -j target.apk 'lib/arm64-v8a/*' -d libs
rg -a -o 'su|/system/bin/su|magisk|frida|gum-js-loop|gmain' libs/*.so | sort -u | head -20
```

The strings you find in the native libraries tell you what the app looks for,
which is far more efficient than hooking blind and waiting for it to die.

## Android

**Start with environment hiding, not hooking.** A well-hidden root defeats most
detection without a single hook, and it does not break when the app updates.

```bash
# Magisk: DenyList the target so the root is invisible to it
#   Settings → Zygisk ON, Enforce DenyList ON, select the target package
# Shamiko (Zygisk module) hides more thoroughly than DenyList alone
# Play Integrity Fix (PIF) module for the attestation layer — see limits below

# Verify what the app can see
adb shell "pm list packages | grep -i magisk"     # should return nothing to the app
```

Then hook what remains:

```bash
objection -g com.target.app explore
# then: android root disable

frida -U -f com.target.app -l anti-root-bypass.js --no-pause
```

Common Java hook points, in the order they usually appear:

```javascript
// File existence checks — the single most common family
Java.use('java.io.File').exists.implementation = function () {
  const p = this.getAbsolutePath();
  if (/su$|magisk|superuser|busybox|xposed/i.test(p)) return false;
  return this.exists();
};

// Runtime.exec("su") and ProcessBuilder
// Build.TAGS containing "test-keys"
// PackageManager.getPackageInfo for known root packages
// System properties: ro.debuggable, ro.secure, ro.build.selinux
```

**Native checks need native hooks.** When Java hooks are in place and the app
still exits, the check is in a `.so`:

```bash
# See which syscall is finding the evidence
frida-trace -U -f com.target.app -i 'stat*' -i 'access' -i 'fopen' -i 'open'
# then edit the generated handlers to lie about the paths it probes
```

## Frida Detection Is a Separate Problem

If the app runs fine rooted but dies the moment you attach, you are fighting
instrumentation detection, and hiding root will not help.

| Check | Counter |
| --- | --- |
| TCP 27042 open, or the D-Bus handshake response | Run `frida-server` on a random port, or use Gadget instead of Server |
| `/proc/self/maps` contains `frida-agent`, `gum` | Rename the agent; use a patched build |
| Thread names `gmain`, `gum-js-loop`, `pool-frida` | Patched Frida builds rename these |
| `/proc/self/task/*/stat` scanning | Same |
| Named pipes and `re.frida.server` strings | Patched build |
| Periodic re-check after launch | Attach *after* the check window, or hook the timer |

The practical answer is a patched Frida (community builds exist specifically
for this) plus Gadget injection rather than a listening server. If detection
still wins, fall back to static analysis plus targeted APK patching — you lose
interactivity but keep progress.

## iOS

```bash
objection -g com.target.app explore
# then: ios jailbreak disable

# Tweak-based, system-wide: Liberty Lite, A-Bypass, Shadow (rootless jailbreaks)
```

What iOS apps check, and what to hide:

- Existence of `/Applications/Cydia.app`, `/bin/bash`, `/usr/sbin/sshd`,
  `/etc/apt`, `/private/var/lib/apt`
- Writability outside the sandbox (`fopen("/private/jailbreak.txt", "w")`)
- `fork()` succeeding, which it should not in a sandboxed app
- `dyld` image list containing MobileSubstrate / substitute
- URL scheme `cydia://` being openable
- `NSFileManager` checks, which are easier to hook than raw `stat`

Hook `stat`, `access`, `fopen`, `getenv("DYLD_INSERT_LIBRARIES")`, and
`_dyld_get_image_name` for the native layer; hook `NSFileManager` methods for
the Objective-C layer. On non-jailbroken devices, repackage with the Frida
gadget (`objection patchipa`) — and expect that to trip attestation.

## What You Cannot Hook

**Hardware-backed attestation is the hard boundary.** Play Integrity's
`MEETS_STRONG_INTEGRITY`, key attestation via the TEE/StrongBox, and Apple's
App Attest are signed by hardware keys and verified on the vendor's servers.
A client-side hook can change what the app *reads*, but it cannot forge a
signature the server validates.

What this means in practice:

- Magisk plus a Play Integrity Fix module can often reach `BASIC` and
  `DEVICE` integrity. `STRONG` requires an unmodified bootloader.
- If the app fails closed on strong integrity, the honest options are a
  non-rooted device with a repackaged app (which itself fails signature
  checks), a device with a stock ROM plus network-layer testing only, or
  agreeing an attestation exemption with the client for the test window.
- **Ask for the exemption.** A test build with attestation disabled is a normal
  engagement request and is far cheaper than days spent losing to a TEE.

Say this in the report rather than quietly reducing scope: "dynamic
instrumentation was not possible against production builds due to hardware
attestation; testing covered X and not Y" is a finding about your coverage, and
hiding it is worse than the limitation.

## Detection Quality Is Itself a Finding

While bypassing, record how good the detection was — clients ask, and it
belongs in the report:

- Does it fail closed (exit) or fail open (log and continue)?
- Is the check result sent to the server, or trusted locally? Local-only checks
  are advisory at best.
- Is it one central function (trivially hooked) or distributed and re-checked?
- Is hardware attestation used, or only filesystem heuristics?

An app whose entire root defense is `File.exists("/system/xbin/su")` deserves a
low-severity note; one that uses server-verified attestation deserves credit.

## Rationalizations to Reject

- *"objection's bypass didn't work, the detection is too strong."* It covers
  the common Java checks. Look at the native layer next.
- *"I hid root, so it should work."* If it dies only under Frida, you are
  fighting instrumentation detection, not root detection.
- *"Play Integrity can be bypassed with Frida."* Not the hardware-backed
  verdicts. Hooks change what the app reads, not what the TEE signs.
- *"I'll patch every check I find."* Distributed checks re-run. Find the
  central decision point, or hide the environment instead.
- *"Root detection is a vulnerability."* It is a control, and a weak one. Its
  absence is a low-severity note, not a headline finding.
- *"I couldn't instrument it, so there's nothing to report."* Report the
  coverage limitation explicitly.

## References

- `testing-mobile-applications` — the assessment this unblocks
- `bypassing-mobile-pinning` — the other reason a mobile app "just fails"
- `analyzing-binaries` — patching native detection routines
- `reporting-security-findings` — how to state a coverage limitation honestly
- Magisk + Zygisk, Shamiko, objection, Frida (and patched builds), Liberty Lite, Shadow
