---
name: testing-mobile-ipc
description: Test mobile inter-process communication and deep link attack surface — exported Android activities, services, receivers and content providers, intent redirection, PendingIntent hijacking, App Links verification, iOS custom URL schemes, Universal Links, and App Groups — using drozer, adb, and Frida. Use when reviewing AndroidManifest.xml exported components, testing deeplinks or URL schemes, or assessing what another app on the device can reach.
---

# Testing Mobile IPC and Deep Links

Every exported component and registered URL scheme is a remote entry point that
does not need the network. A malicious app on the same device — or a web page
the user visits — can invoke them directly, and they are frequently written as
if only the app itself would ever call them.

## When to Use

- Reviewing `AndroidManifest.xml` for exported components
- Testing deep links, App Links, custom URL schemes, or Universal Links
- Assessing content provider and broadcast receiver exposure
- Checking `PendingIntent`, intent redirection, and App Group sharing
- Answering "what can another app on this device do to this one?"

## When NOT to Use

- **Network API testing** — use `testing-apis`
- **Binary-level reversing** — use `analyzing-ios-binaries` or the relevant
  `reversing-*` skill
- **TLS or detection problems blocking you** — use `bypassing-mobile-pinning`
  or `bypassing-root-jailbreak-detection` first
- **The wider assessment** — use `testing-mobile-applications`

## Android: Enumerate the Surface

```bash
apktool d target.apk -o out
# Every component with exported=true, or with an intent-filter and no explicit
# exported attribute on older targetSdk (which defaults to exported)
rg -n 'android:exported="true"|<intent-filter>' -B3 out/AndroidManifest.xml

# Live enumeration
adb shell dumpsys package com.target.app | rg -A3 'Activity Resolver|Receiver Resolver|Service Resolver|Provider'
drozer console connect
#   run app.package.attacksurface com.target.app
#   run app.activity.info -a com.target.app
#   run app.provider.info -a com.target.app
```

**`android:exported` defaults changed** — apps targeting API 31+ must declare
it explicitly, but a component with an intent-filter on an older target is
exported implicitly. Check `targetSdkVersion` before concluding a component is
private.

Also check **permission protection levels**. A component "protected" by a
custom permission declared with `protectionLevel="normal"` is protected by
nothing: any app can request and receive it without user interaction.

```bash
rg -n 'permission android:name|protectionLevel' out/AndroidManifest.xml
```

## Android: Test Each Component Type

```bash
# Activities — can an unauthenticated screen be launched directly?
adb shell am start -n com.target.app/.SomeActivity
adb shell am start -a android.intent.action.VIEW -d "myapp://path?param=value"
adb shell am start -n com.target.app/.WebActivity --es url "https://attacker.example"

# Services
adb shell am startservice -n com.target.app/.ExportedService --es cmd value

# Broadcast receivers
adb shell am broadcast -a com.target.app.ACTION_X --es data value

# Content providers — the highest-yield target
adb shell content query --uri content://com.target.app.provider/users
adb shell content query --uri content://com.target.app.provider/users \
  --where "1=1) UNION SELECT password FROM creds--"
adb shell content read --uri content://com.target.app.provider/files/../../databases/app.db
```

Content providers deserve specific attention because two classic bugs recur:

- **SQL injection** through the `selection`/`projection` arguments, which are
  concatenated into the query far more often than in server code.
- **Path traversal** in `openFile()`, where a provider that serves files from
  its own directory does not canonicalize the requested path, giving any app on
  the device read access to the app's private storage.

## Android: The High-Impact Patterns

**Intent redirection (the "confused deputy" of Android).** An exported
component takes an `Intent` as an *extra* and then starts it. The caller
supplies the inner intent, so it executes with the victim app's identity —
reaching its non-exported components and its permissions.

```bash
rg -n 'getParcelableExtra.*Intent|startActivity\(.*getIntent\(\).*Extra' out/smali*
# Exploit shape: outer intent → exported component → inner intent → private component
```

**PendingIntent hijacking.** A `PendingIntent` created with an implicit base
intent, or without `FLAG_IMMUTABLE`, lets the receiving app fill in the blanks
and cause an action with the sender's identity.

```bash
rg -n 'PendingIntent.get(Activity|Broadcast|Service)' -A3 out/smali*
# Findings: FLAG_MUTABLE (or no flag pre-API-31) plus an implicit base intent
```

**Deep link to WebView.** A deep link parameter that becomes a `loadUrl()`
target turns any web page into a way to render attacker content inside the
app's WebView — with its cookies, its JS bridges, and its file access.

```bash
adb shell am start -a android.intent.action.VIEW -d "myapp://open?url=https://attacker.example"
rg -n 'loadUrl|addJavascriptInterface|setAllowFileAccess|setJavaScriptEnabled' out/smali*
```

**App Links verification.** `autoVerify="true"` only works if
`https://domain/.well-known/assetlinks.json` is correct and reachable. When
verification fails, the link degrades to a disambiguation dialog that another
app can also claim.

```bash
curl -s https://target.example/.well-known/assetlinks.json | jq .
adb shell pm get-app-links com.target.app
```

## iOS

```bash
# Declared URL schemes and associated domains
plutil -p Payload/TargetApp.app/Info.plist | rg -A5 'CFBundleURLSchemes'
codesign -d --entitlements :- Payload/TargetApp.app | rg -A3 'associated-domains|application-groups'

# Trigger a scheme
xcrun simctl openurl booted "myapp://path?param=value"
# On device: open the URL from Safari or Notes
```

**Custom URL schemes are unauthenticated and claimable.** Any app can register
`myapp://`, and if two do, the winner is undefined. Anything reached through a
custom scheme must be treated as attacker-invoked. Universal Links are the
verified alternative:

```bash
curl -s https://target.example/.well-known/apple-app-site-association | jq .
# Must be served over HTTPS, no redirect, correct app ID, correct paths
```

Also check:

- **App Groups** — a shared container between the app and its extensions. Data
  written there is readable by every member, including a weakly-reviewed
  keyboard or share extension.
- **Keychain access groups** — over-broad sharing across an app family.
- **Pasteboard** — the general pasteboard is readable by any app; credentials
  and tokens copied there leak.
- **`application:openURL:options:`** — check whether the handler validates the
  source application and the URL's parameters before acting.

## What Makes It a Finding

Invoking a component is not itself a finding. The finding is what it lets an
unprivileged local app do:

1. **Reach a privileged action without authentication** — a transfer screen, a
   settings change, an account action reachable by deep link past the login gate
2. **Read data it should not** — provider query returning other users' rows, or
   traversal into private storage
3. **Act as the victim app** — intent redirection or PendingIntent hijack
4. **Render attacker content in a trusted context** — WebView with a JS bridge
5. **Leak secrets to the caller** — tokens returned in an activity result,
   written to a shared container, or logged

Test whether the deep link path skips authentication specifically: launch the
target component with the app logged out, and again with a different account.

## Rationalizations to Reject

- *"It's exported but it needs a permission."* Check the protection level.
  `normal` is granted automatically.
- *"Only our own app calls it."* Anything exported is callable by any app, and
  by the browser if it has an intent-filter.
- *"The deep link needs a valid token in the URL."* Test it. Tokens in deep
  links are frequently unvalidated, reusable, or leak through referrer headers.
- *"It's not exported."* Confirm against `targetSdkVersion`, and check whether
  intent redirection reaches it anyway.
- *"iOS URL schemes are fine, we validate the input."* Validate the *caller*
  too — schemes are unauthenticated and claimable by any app.
- *"The provider is read-only."* Read is the finding when the rows belong to
  someone else.

## References

- `testing-mobile-applications` — the wider assessment
- `testing-apis` — the backend those components ultimately call
- `analyzing-ios-binaries` — entitlements and App Group enumeration
- `reporting-security-findings` — severity for local-attacker findings
- drozer, adb, apktool, jadx, objection, Frida
