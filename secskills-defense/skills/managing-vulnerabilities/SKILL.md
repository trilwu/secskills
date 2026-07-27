---
name: managing-vulnerabilities
description: Prioritize and drive remediation of a vulnerability backlog by real risk, not raw CVSS — combining severity with exploitation signals (EPSS, CISA KEV), asset exposure and business context, using SSVC-style decisions, distinguishing reachable from merely present, and tracking remediation and exceptions. Use when triaging scanner output, deciding what to patch first, building a risk-based vulnerability management process, or explaining why a critical CVE is not the top priority.
verified: 2026-07-27
---

# Managing Vulnerabilities

A scanner returns ten thousand findings, most rated High or Critical, and the
team can patch a few hundred a month. Vulnerability management is the function
that decides *which* few hundred — and the default of "sort by CVSS descending"
is close to the worst possible order, because CVSS measures theoretical
severity, not the probability that this vulnerability, on this asset, gets
exploited.

The whole discipline is turning an undifferentiated backlog into a defensible
order of operations that a limited team can actually execute.

## When to Use

- Triaging vulnerability scanner output into a remediation order
- Deciding what to patch first under a fixed remediation budget
- Building or reviewing a risk-based vulnerability management process
- Explaining why a CVSS 9.8 is not this week's top priority
- Deciding whether a finding warrants an exception rather than a fix

## When NOT to Use

- **Working a security *alert* queue** (EDR/SIEM detections) — use
  `triaging-security-alerts`; that is detected activity, this is latent
  weakness
- **Auditing source for new vulnerabilities** — use
  `auditing-code-for-vulnerabilities`
- **Cloud misconfiguration rather than software CVEs** — use
  `hardening-cloud-posture`
- **Exploiting a vulnerability to prove it** — use the relevant offensive skill

## CVSS Is Severity, Not Priority

CVSS base score answers "how bad is this if exploited, in the abstract?" It
does not answer "will it be exploited here?" — which is the question
remediation order actually turns on. The evidence is stark: the large majority
of CVEs are never exploited in the wild, yet most are scored High or Critical.
Sorting by CVSS spends the team's finite capacity on vulnerabilities that will
never be attacked while genuinely exploited ones wait behind them.

Use CVSS 4.0 as one input — the severity term — and combine it with signals
that speak to *probability* and *impact-here*.

## The Three Signals to Combine

### 1. Is it being exploited? — EPSS and KEV

- **CISA KEV (Known Exploited Vulnerabilities).** A curated catalog of CVEs
  with *confirmed, observed* exploitation in the wild. Presence in KEV is the
  single strongest prioritization signal available: it is not a prediction, it
  is a fact of exploitation. Anything in your environment that is on the KEV
  list jumps the queue. For US federal agencies KEV also carries a binding
  remediation deadline; treat those dates as a sensible default even if you are
  not bound by them.
- **EPSS (Exploit Prediction Scoring System).** A daily-updated machine-learning
  probability, from 0 to 1, that a CVE will be exploited **in the next 30 days**.
  It is a *prediction*, not observed fact, and it is a probability, not a
  ranking — a 0.90 means ~90% likely, and most CVEs sit far below 0.10. Use it
  to rank the long tail that is not (yet) in KEV. Because it updates daily,
  re-pull it; a CVE's EPSS can climb sharply when exploitation tooling appears.

KEV and EPSS answer different questions — "known exploited" versus "likely to
be" — and you want both. KEV is the floor of certainty; EPSS orders everything
below it.

### 2. Is it reachable? — exposure and context

A vulnerability that is present but not reachable is not the same as one an
attacker can touch:

- Is the affected service internet-facing, internal-only, or on an isolated
  segment?
- Is the vulnerable code path actually invoked, or is it a dependency present
  but never called? (Reachability analysis — see
  `auditing-supply-chain` for the dependency case.)
- Is there a compensating control — a WAF rule, network policy, a disabled
  feature — that breaks the exploit precondition?
- Does exploitation need authentication, local access, or user interaction
  that the placement makes unlikely?

An internet-facing, unauthenticated, KEV-listed RCE and an internal,
authenticated, same-CVSS bug are not the same priority, whatever the score
says.

### 3. What does it protect? — asset value

The same vulnerability on a domain controller, a crown-jewel database, and a
developer's throwaway VM warrants three different urgencies. Tie the finding to
asset criticality; a vulnerability management programme without an asset
inventory is ranking blind.

## Decide with SSVC, Not a Single Number

Rather than collapsing everything into one score, a decision-tree approach
(SSVC — Stakeholder-Specific Vulnerability Categorization) asks the questions
above in order and lands on an action: **exploitation status → exposure →
automatable → impact → {track / track\* / attend / act}.** The value is that
each decision is *explainable* to the team doing the work and to the risk owner
signing the exceptions, in a way "it scored 8.7" never is.

Whatever the framing, the output must be an **ordered, executable list with
owners and dates**, not a risk score. The programme's product is patched
systems, not a dashboard.

## Track Remediation and Exceptions Honestly

- **A finding is open until verified fixed**, not until a ticket is closed.
  Re-scan to confirm; "patched" and "no longer detected" are different claims.
- **Exceptions are decisions with an owner and an expiry**, not silent
  suppressions. "Accepted risk" with no name and no review date is how a KEV
  CVE sits open for a year.
- **Recurrence is a process finding.** The same vulnerability returning after a
  fix means the base image, the golden template, or the pipeline is
  reintroducing it — fix the source, not the instance, the same way cloud
  guardrails beat point-fixes.

## Rationalizations to Reject

- *"It's a 9.8, so it's top priority."* CVSS is severity, not probability of
  exploitation. A 9.8 that is not in KEV, has a low EPSS, and sits on an
  isolated internal host ranks below a 7.5 that is KEV-listed and
  internet-facing.
- *"It's only a 5.3, we can ignore it."* Not if it is KEV-listed and reachable.
  Observed exploitation outranks a mediocre severity score.
- *"We patch everything Critical within 30 days."* A blanket SLA by severity
  spends the budget by the wrong axis. Patch *exploited and reachable* within
  days; let unexploited, unreachable Criticals follow.
- *"The dependency is vulnerable, so we're vulnerable."* Only if the vulnerable
  code path is reachable. Present-but-uncalled is real backlog but not the same
  urgency as invoked.
- *"EPSS is low, so it's safe."* EPSS is a 30-day prediction that moves. Re-pull
  it, and remember KEV overrides it — observed beats predicted.
- *"We closed the ticket."* Closing a ticket is not fixing a vulnerability.
  Re-scan and verify, or it is still open.
- *"It's an accepted risk."* Accepted by whom, reviewed when? An exception with
  no owner and no expiry is an unmanaged vulnerability wearing a label.

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

- `triaging-security-alerts` — the detected-activity counterpart to this
  latent-weakness work; both rank by real risk under finite capacity
- `auditing-supply-chain` — dependency reachability, the input to signal 2 for
  library CVEs
- `hardening-cloud-posture` — the config-misconfiguration counterpart to
  software CVEs
- `reporting-security-findings` — communicating prioritized risk to owners
