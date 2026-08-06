---
name: reversing-obfuscated-javascript
description: Reverse engineer minified, bundled, and obfuscated browser/Node JavaScript — unpacking webpack chunks, recovering source from sourcemaps, undoing obfuscator.io string-array and control-flow obfuscation with webcrack/synchrony/restringer, and locating a signing or crypto routine in a live bundle via Chrome DevTools. Use when a page ships a huge minified bundle, when code is full of _0x hex identifiers and a rotated string array, when a .js.map is reachable, or when you must find where a request signature or token is computed.
verified: 2026-08-07
---

# Reversing Obfuscated JavaScript

Client-side JavaScript ships the whole program to the reader — there is no
stripped binary here, only code deliberately made unreadable. That changes the
job: you are almost never recovering *missing* information, you are undoing a
transformation. Identify the transformation first, reverse it with the tool
built for it, and fall back to hand-written AST passes only for the custom
layer no off-the-shelf tool knows.

## When to Use

- A page or extension ships a large minified/bundled `.js` you need to read
- Code is full of `_0x1234` identifiers, a big string array, and a rotation IIFE
  at the top — the obfuscator.io signature
- A `.js.map` sourcemap is reachable, or webpack left `//# sourceMappingURL`
- You must locate where a request signature, HMAC, token, or crypto key is
  computed inside a running bundle
- Reproducing a client-side algorithm (an anti-bot signal, a licence check, a
  paywall gate) from the shipped code

## When NOT to Use

- **React Native / Hermes mobile bundles** (`index.android.bundle`,
  `main.jsbundle`, Hermes magic bytes) — use `reversing-react-native-apps`.
- **A custom bytecode VM or virtualized-JS obfuscator** where control flow is
  interpreted, not just flattened — that is devirtualization; use
  `unpacking-protected-binaries` for the VM-lifting approach.
- **Malicious JS in a compromised site or npm package** where the goal is IOCs
  and behaviour, not readability — use `hunting-web-backdoors` for planted web
  payloads and `auditing-supply-chain` for a malicious package.
- **Testing the web app itself** (the endpoints the JS calls, XSS, auth) — use
  `testing-web-applications`; come back here only to recover a client-side
  algorithm it needs.
- **WASM modules** loaded by the page — that is `analyzing-binaries` territory.

## Identify the Layer Before Touching a Tool

Running the wrong deobfuscator produces plausible garbage. Read the first few
hundred bytes and classify:

| What you see | Transformation | Reverse it with |
| --- | --- | --- |
| Short names, no whitespace, readable strings | Minification only | An unminifier / prettier + rename |
| `webpackChunk`, a module map `{123: function(e,t,n){…}}` | Webpack/Rollup bundling | Unbundle to per-module files |
| `//# sourceMappingURL=…` or a reachable `.map` | Nothing — the source is *right there* | Sourcemap recovery |
| `_0x` hex names + one big string array + a rotation IIFE | obfuscator.io string-array | webcrack / synchrony / restringer |
| Nested ternaries, `while(true){switch(_0x..)}` dispatcher | Control-flow flattening | AST pass to relink the switch |
| `debugger` in a `setInterval`, self-defending function | Anti-debug / self-defense | Strip the guard before other passes |

Most real bundles are **layered**: webpack on the outside, obfuscator.io on a
few modules, a hand-rolled string cipher on the one function that matters.
Peel outermost first.

## Sourcemaps: Try This First, Always

A reachable sourcemap ends the job before it starts — it contains the original,
pre-transform source. Check for it every time, because a large fraction of
"obfuscated" production bundles ship or leak one:

- The `//# sourceMappingURL=` comment at the bundle's end, and the sibling
  `.js.map` even when the comment was stripped (try `<bundle>.map`).
- Webpack dev artifacts and source in `webpack://` paths inside the map.
- Recover files with a sourcemap consumer — `unwebpack-sourcemap` or a short
  `source-map` script walks `sourcesContent` back to a directory tree.

Treat a leaked production sourcemap as a finding in its own right when you are
assessing the app, not just a convenience.

## Unbundling and Deobfuscation

**`webcrack` is the first tool for a bundle**, because it does three of the
layers at once: unminify, unpack webpack/browserify into per-module files, and
undo obfuscator.io string-array and control-flow obfuscation. Run it, then read
the module tree it produces rather than the single blob.

For a bundle that is *only* obfuscator.io, a dedicated deobfuscator is often
cleaner: **`synchrony`** or **`restringer`** both resolve the string array,
reverse the rotation, inline the decoder calls, and flatten the trivial control
flow. Compare their output — they fail on different edge cases.

When no tool fully handles the custom layer, **write an AST pass** with Babel:
parse to an AST, `@babel/traverse` to find the pattern (a specific decoder call,
a constant-folded expression, the flattening dispatcher), transform the nodes,
and regenerate. This is the durable skill — obfuscators change, but string-array
decoding, constant folding, and dead-branch elimination are the same AST
operations every time. Prototype the matcher in AST Explorer against the real
code before scripting it.

Two failure modes to expect:

- **A deobfuscator that runs the code to "evaluate" the string decoder** can
  execute a payload. For untrusted or malicious bundles, do the string
  resolution statically or in an isolated sandbox — never `eval` an unknown
  bundle on your host to read it.
- **Self-defending / debug-protection** re-obfuscates or spins a `debugger`
  loop when tampered with. Strip the guard function first (delete the node,
  or override `setInterval`) or every downstream pass fights it.

## Finding a Routine in a Live Bundle

When static reading is slow — a signing function buried in a megabyte of
modules — drive the running page with Chrome DevTools instead:

- **Break on the behaviour, not the code.** XHR/fetch breakpoints stop when the
  signed request fires; the call stack then walks straight back through the
  signing function. DOM and event-listener breakpoints do the same for
  UI-triggered logic.
- **Pretty-print** in the Sources panel (`{}`) makes a minified function
  steppable without any offline work.
- **Hook property access** from the console — `Object.defineProperty` or a
  `Proxy` on the object whose method computes the value logs every call and
  argument with a stack trace, so you see inputs and outputs without reading
  the math.
- **Override the file** with a local, prettified, `console.log`-instrumented
  copy (DevTools Local Overrides) to watch the real values flow at runtime.

Runtime observation and static reading are complementary: DevTools tells you
*which* function matters; the AST work tells you *what it computes* so you can
reproduce it offline.

## Scope and Authorization

Reading and deobfuscating a bundle you lawfully retrieved is analysis. Two
edges need care. Reproducing and *replaying* a request-signing routine against
the origin — the usual reason to reverse an anti-bot signal — acts against that
service and needs the same authorization as any other testing; keep it to
systems you are permitted to test, and see `testing-web-applications`. And a
sourcemap or bundle pulled from a third-party site is that party's code:
recovering it for a security assessment you are engaged to do is fine, lifting a
proprietary algorithm for reuse is a different matter.

## Rationalizations to Reject

- **"It's obfuscated, so it's slow manual work."** Classify first — a reachable
  sourcemap or a clean `webcrack` run turns hours into minutes. Hand-reading is
  the last resort, not the first move.
- **"webcrack's output has a weird spot, so it failed."** Layered obfuscation
  means one tool clears the outer layers and leaves the custom inner one. That
  residue *is* the interesting function; switch to an AST pass on it, don't
  restart.
- **"I'll just eval the string-decoder to get the plaintext."** On an untrusted
  bundle that runs attacker code on your host. Resolve strings statically or
  sandboxed.
- **"The variable names are gone, so the logic is gone."** Minification and
  obfuscation rename and reshape; they do not delete. Unlike a stripped native
  binary, the full program is present — you are undoing a transform, not
  reconstructing lost information.
- **"DevTools is for debugging, not reversing."** A fetch breakpoint plus a
  property hook locates a signing routine faster than reading the bundle, and
  gives you live inputs and outputs for free.

## References

- `reversing-react-native-apps` — Hermes/RN mobile JS bundles
- `unpacking-protected-binaries` — VM-based / virtualized obfuscation
- `hunting-web-backdoors` — malicious planted web JS
- `testing-web-applications` — testing the endpoints a recovered algorithm calls
- `reviewing-cryptography` — once a client-side crypto/signing routine is recovered
