---
name: reversing-browser-extensions
description: Reverse engineer and security-review Chrome/Firefox browser extensions — unpacking the CRX/XPI, reading the manifest for over-broad permissions, and tracing the trust boundary between page, content script, background service worker, and native messaging host. Use when analyzing a suspicious or over-permissioned extension, auditing your own extension's privilege model, or investigating how a content script exposes privileged APIs to a web page.
verified: 2026-08-07
---

# Reversing Browser Extensions

A browser extension is a small privileged program wedged next to every page the
user visits. Its security is almost entirely about a boundary: the content
script runs beside untrusted web content but can talk to a background context
that holds real permissions — cookies, tabs, the network, sometimes a native
process. Reversing an extension is reading that boundary and finding where the
privileged side trusts the unprivileged one.

## When to Use

- Analyzing a suspicious, over-permissioned, or unknown extension's behaviour
- Auditing an extension's manifest and message-passing for privilege leaks
- Investigating how a content script exposes background/native capabilities to a
  page
- Recovering what an extension actually does versus what its store listing claims

## When NOT to Use

- **Deobfuscating the extension's bundled JavaScript** as a code-reading problem
  — use `reversing-obfuscated-javascript` for the bundle, then return here for
  the privilege model.
- **Detonating and extracting IOCs from a malicious extension** as part of an
  incident — use `analyzing-malware`.
- **Testing the web application** the extension interacts with —
  `testing-web-applications`.
- **A desktop app that happens to embed a browser** — `testing-thick-clients`.

## Get the Code and Read the Manifest

An extension ships as a **CRX** (Chrome) or **XPI** (Firefox) — both are ZIP
archives; unzip and read. You can pull a published extension from the store's
CRX endpoint, or straight from the browser profile's `Extensions` directory.

The **manifest** is the map. Read it before any code:

- **`manifest_version`** — MV2 (background page, `webRequest` blocking) vs MV3
  (background **service worker**, `declarativeNetRequest`, remote code
  forbidden). The version changes where the privileged logic lives and how it
  persists.
- **`permissions` and `host_permissions`** — `<all_urls>`, `tabs`, `cookies`,
  `webRequest`, `debugger`, `nativeMessaging`, `scripting`. Judge each against
  what the extension claims to do; `<all_urls>` + `cookies` on a "dark theme"
  extension is the tell.
- **`content_scripts`** — which pages the extension injects into, and therefore
  which pages' content it is exposed to.
- **`externally_connectable`** — which web origins may send it messages
  directly; a permissive value is an attack surface.
- **`web_accessible_resources`** — extension files a page can load, which can
  leak the extension's presence or expose an injectable resource.
- **`content_security_policy`** — a loosened CSP (`unsafe-eval`, remote script)
  is a code-injection surface.

## The Trust Boundary

Extensions are isolated by design; the bugs are in the seams between contexts:

- **Page ↔ content script.** The content script runs in an *isolated world* —
  it shares the DOM with the page but not JS variables. The leak is through the
  DOM and `window.postMessage`: a content script that acts on `postMessage` data
  without checking `event.origin`/`event.source` lets any page in its
  injection scope drive it.
- **Content script → background/service worker.** The content script relays
  messages to the background context to do privileged work (`chrome.runtime`
  messaging). If the background handler does not validate the **sender** and the
  message shape, a compromised or malicious page (via the content script) reaches
  privileged APIs. This is the central extension bug: *privileged operations
  gated only by a message the page can influence.*
- **`onMessageExternal` / `externally_connectable`.** A web page listed here
  talks to the background directly — same validation question, one hop shorter.
- **Native messaging.** `nativeMessaging` connects the extension to a local
  native host binary. A weakly validated message path here is browser-to-native
  code execution; trace what the native host does with what it receives.

For each privileged capability, answer: what input reaches it, and from how far
out (background only, content script, or an arbitrary page)?

## What to Flag

- **Over-broad permissions** disproportionate to function.
- **Unvalidated message senders** on `runtime.onMessage` /
  `onMessageExternal` — the privilege-escalation path from page to extension.
- **`postMessage` handling without origin checks** in content scripts.
- **Remote code / `eval`** or a CSP that permits it (also an MV3 policy
  violation).
- **Data exfiltration** — traffic to endpoints unrelated to the stated purpose;
  reading page content, form fields, or cookies and sending them out.
- **Native messaging** to a host that acts on unvalidated input.
- **Update/supply-chain risk** — an extension that loads remote config or code,
  or one whose ownership recently changed.

## Deobfuscate When Needed

Store extensions are frequently minified or bundled, and malicious ones
obfuscated. When the code is unreadable, hand the bundle to
`reversing-obfuscated-javascript` — unbundle and deobfuscate there, then read
the recovered logic against the trust boundary above. Debug the live extension
in the browser's extension DevTools to watch the message passing at runtime.

## Rationalizations to Reject

- **"The store reviewed it, so it's fine."** Store review is shallow and
  bypassed regularly; an ownership change can turn a clean extension malicious in
  one update. Read the code it actually ships.
- **"Content scripts are sandboxed, so page compromise can't reach the
  extension."** The isolated world separates JS, not the DOM or `postMessage`. An
  unchecked message handler is the bridge.
- **"The background just relays a message."** If it relays a *page-influenced*
  message into a privileged API without validating the sender, that relay is the
  vulnerability.
- **"It only asks for the permissions it needs."** Verify against behaviour.
  `<all_urls>`, `cookies`, `debugger`, and `nativeMessaging` are the ones that
  turn a small bug into a large one.
- **"It's minified, so I can't review it."** Minification is reversible; unbundle
  and deobfuscate first, then review.

## References

- `reversing-obfuscated-javascript` — unbundling and deobfuscating the extension's JS
- `analyzing-malware` — detonation and IOCs for a confirmed-malicious extension
- `testing-web-applications` — the sites and APIs the extension talks to
- `auditing-supply-chain` — ownership-change and remote-code update risk
