---
name: testing-thick-clients
description: Security-test desktop thick-client applications (.NET/WPF, Java, Electron, native Win32) against their local and network attack surface — proxying non-HTTP traffic, extracting secrets and DB connection strings from config/registry/memory, bypassing client-side trust controls, and reviewing update channels and DLL search order. Use when assessing an installed desktop app that talks to a backend, when Burp sees no traffic from a fat client, or when a two-tier app connects straight to a database.
---

# Testing Thick Clients

A thick client puts part of the application on the tester's own machine, and
that is the whole opportunity: the binary, its config, its memory, and its
traffic are all reachable. The recurring failure in these apps is trusting the
client — enforcing authorization, hiding functionality, or holding secrets on a
box the user controls. The job is to enumerate that surface and show where the
trust is misplaced.

## When to Use

- Assessing an installed desktop application (.NET/WPF, Java/Swing, Electron,
  Qt, native Win32) that communicates with a backend
- A fat client where Burp shows nothing because the traffic is not HTTP or not
  proxy-aware
- A two-tier app that connects directly to a database
- Reviewing local storage, IPC, update integrity, and DLL loading of a desktop
  app

## When NOT to Use

- **Browser/web apps and their APIs** — use `testing-web-applications` and
  `testing-apis`; come here only for an installed desktop client.
- **Electron internals as a JS reversing problem** (unpacking `app.asar`,
  deobfuscating the bundle) lean on `reversing-obfuscated-javascript` for the
  code, and this skill for the app's trust surface.
- **Pure reverse engineering of the binary** with no security-test goal —
  `analyzing-binaries`, or `analyzing-dotnet-assemblies` for managed code.
- **Mobile apps** — `testing-mobile-applications`.
- **Turning a memory-corruption crash into an exploit** — that is
  `exploiting-memory-corruption`.

## Map the Architecture First

The single most important question is how many tiers the app has, because it
changes what a compromised client gets you:

- **Two-tier** (client → database directly): the client must hold database
  credentials, and a connection string in config or memory gives you the same
  direct database access the app has. This is the highest-value finding in a
  thick client; look for it first.
- **Three-tier** (client → app server → database): the client talks to an API,
  and the surface resembles a web test *plus* the local attack surface below.

Then identify the stack — managed (.NET, Java), Electron, or native — because it
dictates the tools for every step that follows.

## Local Attack Surface

Everything the app stores on the tester's machine is readable:

- **Config and secrets.** Connection strings, API keys, and encryption keys in
  `app.config`/`.exe.config`, `.ini`, JSON, the registry, or `%APPDATA%`. Watch
  for secrets "encrypted" with a key that ships in the same binary — recover the
  key and it is plaintext.
- **Filesystem and registry activity.** Run **Procmon** (Sysinternals) while
  exercising the app to see every file and registry key it touches; **Regshot**
  diffs the registry across an action. Weak ACLs on an install directory or a
  service enable local privilege escalation.
- **Local databases.** SQLite and similar stores often cache data or tokens;
  open them directly.
- **Memory.** Secrets decrypted for use sit in the process; `strings` on a dump,
  or **Process Hacker / System Informer**, recovers them.
- **The binary.** Decompile managed code with **dnSpy/ILSpy** (.NET, plus de4dot
  for obfuscation) or a Java decompiler; hardcoded logic, keys, and hidden
  endpoints fall out.

## Intercepting Non-HTTP Traffic

When the client is not proxy-aware or does not speak HTTP, Burp alone sees
nothing:

- **HTTP but proxy-unaware** — force it through a proxy (system proxy,
  proxifier-style redirection, or hosts/DNS), and trust the proxy CA. .NET apps
  often ignore the system proxy until configured.
- **Non-HTTP TCP/TLS** — **mitmproxy** in transparent/reverse mode, or an
  invisible-proxy setup, plus **Wireshark** to first understand the protocol.
  Legacy write-ups mention Echo Mirage; on modern Windows it is unreliable, so
  prefer runtime hooking.
- **Runtime hooking** — **Frida** on the desktop process intercepts the
  send/recv or the TLS routine directly, which beats fighting the network layer
  when the app pins or wraps its own crypto.

## Client-Side Trust — the Core Class

Assume every control enforced only in the client is bypassable, and prove it:

- **Disabled buttons, hidden menus, and "admin" features gated by a client
  flag** — flip the flag in memory or the decompiled binary; if the server does
  not re-check, the feature is yours.
- **Client-side input validation and business rules** — bypass them at the
  proxy and see whether the server re-validates.
- **Authorization decided in the client** — the classic thick-client bug: the
  UI hides what the user may not do, but the backend authorizes on identity
  alone. Test the action, not the button.

## Update Channel and DLL Loading

- **Update integrity** — if the app fetches updates over HTTP, or over HTTPS
  without signature verification, the update channel is a code-execution path.
  Check how the updater validates what it installs.
- **DLL search-order hijacking** — a missing DLL loaded from a writable
  directory on the search path is local code execution in the app's context;
  enumerate the app's imports and load paths.

## Scope and Authorization

A thick client's backend is production infrastructure, so the same scope and
authorization rules as any network test apply — the local analysis is yours to
do freely, but anything the client *sends* reaches the client's estate.

The two-tier case needs an explicit call-out to the client: recovering a
database connection string yields **direct, often highly privileged database
access** that bypasses whatever the application layer would have enforced.
Demonstrate the access to prove the finding; do not go rummaging through
production data beyond what shows impact, and record it in the engagement's
access inventory (`maintaining-engagement-state`).

## Rationalizations to Reject

- **"Burp shows no traffic, so there's nothing to test."** The client is not
  proxy-aware, or the protocol is not HTTP. Force the proxy or hook the process;
  the traffic is there.
- **"The secret is encrypted in the config."** If the key ships in the binary,
  it is obfuscation, not encryption. Recover the key and read it.
- **"The admin feature is greyed out, so it's protected."** Client-side gating
  is not authorization. Flip it and check whether the server re-enforces — that
  is the finding.
- **"It's a desktop app, the backend is out of reach."** A two-tier app hands
  you its database credentials. Look for the connection string before assuming
  the data tier is safe.
- **"Local-only issues are low severity."** Weak install ACLs, DLL hijack, and
  an unsigned updater are local code-execution and privilege-escalation paths,
  not cosmetic.

## References

- `testing-web-applications` — the backend API surface of a three-tier client
- `analyzing-dotnet-assemblies` — decompiling managed .NET clients
- `reversing-obfuscated-javascript` — Electron app bundles
- `exploiting-memory-corruption` — if a native client has a memory bug
- `maintaining-engagement-state` — recording recovered DB access and credentials
