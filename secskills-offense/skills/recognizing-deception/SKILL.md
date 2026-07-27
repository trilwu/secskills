---
name: recognizing-deception
description: Recognize defensive deception during an engagement — honeypots, honeytokens and canary tokens, decoy AD accounts and shares, canary files, and deceptive cloud credentials — before interacting with them, and handle a suspected decoy without burning the engagement. Use when a target is unexpectedly easy, when credentials or a service appear in an implausible place, when a privileged account has no logon history, when a file or bucket looks like bait, or when deciding whether to use credentials of unknown provenance.
verified: 2026-07-27
---

# Recognizing Deception

Every other skill in this collection assumes the environment is telling you the
truth. Deception technology exists specifically to break that assumption, and
it is the failure mode an automated or semi-automated tester is least equipped
to catch.

The distinction that matters: careful evidence-handling protects you against
conclusions *you* invented. It does nothing against a false belief the
environment deliberately planted. A honeypot presenting a convincingly
vulnerable service produces real banners, real responses, and real artifacts.
Every verification step you would normally run confirms it, because the
evidence is genuine — it was manufactured to be.

Assume competent defenders have planted something. Your job is to notice
before you touch it, because **most deception fires on first use, and first
use cannot be undone.**

## When to Use

- Anything is markedly easier than the rest of the environment
- Credentials turn up somewhere convenient — a share, a wiki, a config, a
  pastebin-shaped file
- A privileged account exists with a SPN, a weak password, and no logon history
- A service answers with a vulnerable banner but behaves oddly under real use
- You are about to use credentials whose provenance you cannot state
- A file, bucket, or database is named to attract attention
  (`passwords.xlsx`, `backup-prod`, `domain_admins.txt`)
- Before authenticating with anything recovered from an unexpected location

## When NOT to Use

- **Evading detection generally** — that is engagement OPSEC, not deception
  recognition; a canary is not something you evade, it is something you avoid
  triggering
- **Analysing an adversary's own decoys during an incident** — use
  `responding-to-incidents` and `producing-threat-intelligence`
- **Building a deception capability** — this skill is about encountering
  deception, not deploying it
- **A finding that is merely surprising** — real environments contain real
  misconfigurations; see the base-rate discussion below before crying honeypot

## The Economics Are Against You

Deception is cheap to deploy and expensive to trip:

| | Attacker cost | Defender benefit |
| --- | --- | --- |
| Canary token in a document | One click to trigger | High-fidelity alert, near-zero false positives |
| Honeyuser in AD | One Kerberoast | Alert plus a cracked-password timeline |
| Decoy AWS key | One `sts get-caller-identity` | Alert with your source IP and user agent |
| Honeypot service | One connection | Full interaction capture, your tooling fingerprinted |

A canary alert is one of the very few signals a SOC treats as automatically
true. There is no benign explanation to hide behind, and the alert carries
your source address and often your tooling's fingerprint. Tripping one
typically ends the covert phase of an engagement immediately.

## Signals, By Type

### Honeytokens and canary tokens

The highest-frequency class, and the one that fires on *use* rather than on
discovery. Common forms: AWS keys, Office documents with a callback, DNS
tokens, URL tokens, cloned-website tokens, SQL Server rows, Windows directories, Kubeconfig files.

Signals:

- Credentials in a location with no operational reason to hold them — a
  world-readable share, a wiki page, a `README`, a desktop file
- An AWS key that is syntactically valid but appears in isolation, with no
  surrounding infrastructure, tooling config, or commit history
- Documents that are plausible but inert — a spreadsheet with no formulas, a
  `.docx` whose only interesting content is its filename
- Anything staged for discovery: correct name, convenient location, no
  supporting context

**A canary AWS key alerts on the first API call, including
`sts get-caller-identity`.** There is no safe reconnaissance call. Treat key
material of unknown provenance as live until you can explain how it got there.

### Active Directory decoys

- Privileged account, SPN set, weak password, `lastLogon` empty or ancient —
  a Kerberoastable account nobody has ever authenticated as is bait
- Accounts whose `whenCreated` clusters with other suspicious accounts
- `Description` fields containing credentials — a classic real
  misconfiguration and a classic decoy, so provenance matters more than usual
- Shares with attractive names and no access history
- Objects that appear in enumeration but have no group membership, no manager,
  no ownership relationships — real accounts accrete relationships

### Deceptive services

- Banner advertises a version with a famous CVE, but behaviour under real
  interaction is inconsistent with that version
- Service is reachable from a segment that should not reach it
- Response timing is uniform in a way real applications are not
- The host runs an implausible service combination, or a service with no
  business function on that host
- Exploitation "succeeds" but the resulting shell has no history, no other
  users, no realistic filesystem, and suspiciously clean logs

### Cloud decoys

- S3 buckets, storage accounts, or secrets named to attract enumeration
- IAM users with permissive-looking policies and no CloudTrail history
- Resources tagged inconsistently with the rest of the account

## Base Rates Cut Both Ways

Real environments are genuinely bad. Credentials really do sit in shares,
service accounts really are Kerberoastable, and buckets really are public. If
you label every finding a honeypot you will report nothing and miss the actual
compromise path.

The discriminator is **supporting context, not attractiveness**:

- A real misconfiguration has a *history* — commit history, access logs,
  logon history, related infrastructure, other users, adjacent mess.
- A decoy is *isolated*. It exists to be found and nothing else uses it.

So the question is never "is this too good to be true?" It is: **what else in
this environment depends on this thing existing?** If the answer is nothing,
slow down.

## What To Do With a Suspected Decoy

1. **Do not authenticate, connect, or call the API.** Discovery is usually
   silent; use is not. This is the whole decision.
2. **Record it** — location, exact artifact, how you found it, why you suspect
   it. This is evidence for the report either way.
3. **Keep enumerating elsewhere.** A suspected decoy is a reason to route
   around, not to stop.
4. **Raise it with the client contact** rather than testing your hypothesis
   against production. Ask whether deception is deployed and in scope. Many
   engagements exclude it; some clients deploy it specifically to test the
   blue team's response to *you*.
5. **If you already tripped it, say so immediately.** A canary alert with a
   known, declared cause is an engagement note. The same alert investigated
   as a live intrusion burns the client's IR capacity and your credibility.
   Concealing it is the actual serious mistake.

Deception in the environment is a **positive finding** worth reporting: it
means the defenders invested in high-fidelity detection. Say so.

## Rationalizations to Reject

- *"It was in scope, so using it was fine."* Scope governs authorization, not
  wisdom. Tripping a canary inside scope still ends your covert phase and
  still consumes the client's incident response.
- *"I only ran one harmless call to check."* For a canary token there is no
  harmless call. `sts get-caller-identity`, a single DNS lookup, opening the
  document — that is the trigger, in full.
- *"The banner and the CVE matched, so it was real."* The evidence being
  genuine is exactly the design. Manufactured evidence verifies correctly.
- *"Real environments are messy, so this is probably just a misconfiguration."*
  Often true — which is why the test is supporting context, not plausibility.
  Isolated artifacts with no dependents are the tell.
- *"It's just a lab-looking box, probably a decommissioned host."* Uniform
  timing, no user history, and a clean filesystem describe a honeypot as
  readily as a stale host, and you cannot distinguish them from outside.
- *"I'll mention it in the report at the end."* A tripped canary is time-
  critical for the client's SOC. Delayed disclosure turns your engagement note
  into their multi-hour investigation.
- *"Reporting that I tripped it makes me look bad."* Tripping deception is a
  normal engagement event. Hiding it and letting the SOC chase a phantom
  intrusion is a professional failure.

## Reading External Sources

Fetch public advisories, specifications, and vendor reports as Markdown:

```bash
curl -sL "https://defuddle.md/<url>"      # scheme in the path is optional
```

This strips page boilerplate — roughly 78% fewer tokens on a prose page — and
returns the full text rather than a summary, so you can grep it and trust a
negative result.

Three things it is not for. Fetch JSON and API responses raw, because
readability extraction mangles structured data. Fetch authenticated or
JavaScript-rendered pages directly, because it retrieves them anonymously. And
never route **adversary infrastructure** (phishing links, C2, malware hosting),
**client-owned hosts**, or **engagement URLs** through it — the request leaves
your machine to a third party, and for live adversary infrastructure it also
tips off the operator.

Some sites block the extractor and return an error blob rather than the page —
`{"error":"Failed to fetch: 418 I'm a teapot"}` from freedesktop.org, for
instance. That is the fetch being refused, **not** the source saying the thing
does not exist. Re-fetch the URL directly before drawing any conclusion from
it.

## References

- `maintaining-engagement-state` — recording provenance, which is what makes
  the "where did this credential come from?" question answerable
- `performing-reconnaissance` — where isolated artifacts usually surface first
- `attacking-active-directory` — Kerberoasting and share enumeration, the two
  operations most likely to meet an AD decoy
- `establishing-persistence` — canary files and folders are commonly placed
  where persistence is written
