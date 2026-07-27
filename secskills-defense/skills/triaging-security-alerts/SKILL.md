---
name: triaging-security-alerts
description: Work a security alert queue to a defensible disposition — separating true positives from false positives and benign true positives, reasoning about base rates before escalating, ordering enrichment by cheapest discriminator, time-boxing, and documenting negative results so a closed alert is evidence rather than a guess. Use when triaging SOC or EDR alerts, deciding whether an alert warrants incident response, working through an alert backlog, or determining why a detection keeps firing.
verified: 2026-07-27
---

# Triaging Security Alerts

Triage is the highest-volume work in security and the least written about. The
output is a **disposition you can defend later** — most often to someone asking
why an alert that preceded a breach was closed.

Three properties make it hard. The overwhelming majority of alerts are not
incidents, so the prior is against you on every single one. The cost of the two
error types is wildly asymmetric — a wrongly escalated alert wastes hours, a
wrongly closed one costs the breach. And the queue keeps arriving, so unbounded
care on one alert is care stolen from the next.

## When to Use

- Working an alert queue from a SIEM, EDR, or cloud security tool
- Deciding whether an alert becomes an incident
- Reworking a backlog, or a specific alert that keeps recurring
- Reviewing another analyst's disposition
- Determining whether a noisy detection should be tuned or removed

## When NOT to Use

- **The alert is already confirmed malicious** — stop triaging and use
  `responding-to-incidents`; triage ends where response begins
- **Searching for compromise with no alert to start from** — use
  `hunting-threats`; a hunt is hypothesis-driven, triage is queue-driven
- **Rewriting the rule** — use `engineering-detections` or `writing-sigma-rules`;
  feed your triage findings to it rather than tuning in place mid-queue
- **Analysing the sample an alert pointed at** — use `analyzing-malware`
- **Investigating a specific compromised host in depth** — use
  `investigating-windows-endpoints` or the relevant cloud investigation skill

## Three Dispositions, Not Two

The common failure is a binary true/false frame. There are three, and
conflating the last two destroys your detection programme:

| Disposition | Meaning | Correct action |
| --- | --- | --- |
| **True positive** | Detection fired correctly, activity was malicious | Escalate to incident response |
| **Benign true positive** | Detection fired correctly, activity was authorized | Close, and record the authorizing context. **Do not** tune the rule away |
| **False positive** | Detection logic was wrong — it did not match what it claims to match | Close, and send it to detection engineering as a logic defect |

An admin legitimately dumping LSASS for a memory test is a *benign true
positive*: the rule worked perfectly. Filing it as a false positive leads
someone to weaken a rule that is functioning exactly as designed. Over a year
that is how a detection programme quietly dies.

## Base Rates Decide More Than Evidence Does

Most triage errors are not evidence-reading errors. They are prior-probability
errors.

Take a detection that is 99% accurate, firing across 10,000 hosts where 1 is
actually compromised. It produces roughly 100 false alerts and 1 true one. **A
positive alert is about 1% likely to be a real compromise** — even at 99%
accuracy. This is why "the tool flagged it" carries almost no weight on its
own, and why an analyst who escalates on tool severity alone will be wrong
almost every time.

The practical consequences:

- **Severity is a property of the rule, not of the alert.** It was assigned by
  whoever wrote the detection, before your environment existed.
- **Ask what else would produce this signal.** If routine administration,
  backup software, or a vulnerability scanner explains it, that explanation is
  far more likely than compromise before you have contrary evidence.
- **Corroboration beats confidence.** Two weak independent signals pointing the
  same way move the posterior much further than one strong signal, because
  their benign explanations rarely coincide.
- **Rare things are rare — but rarity is not innocence.** The point is to make
  the prior explicit so evidence has to actually overcome it, not to explain
  every alert away.

## Order Enrichment by Cheapest Discriminator

Work the question that most cheaply splits benign from malicious. Do not run a
fixed enrichment checklist.

1. **What is this asset and who uses it?** A domain controller and a
   developer's laptop generate different priors for identical activity.
2. **Is this normal for *this* host or user?** Frequency and history first. An
   action that ran daily for eight months is a baseline, not an event.
3. **Was it authorized?** Change tickets, maintenance windows, deployment
   pipelines. Most benign true positives resolve here.
4. **What is the parent and the chain?** Provenance discriminates far better
   than the artifact itself. `powershell.exe` is meaningless; spawned by
   `winword.exe` is not.
5. **Only then, external reputation.** Hash and IOC lookups are the *last*
   cheap step, not the first. A clean reputation proves nothing about targeted
   activity, and a dirty one still needs the local context above.

Stop as soon as one of these settles it. Running every step on every alert is
how the queue wins.

## Time-Boxing and Escalation

Set a bound before you start — commonly 15 minutes for a routine alert. When
it expires, you must choose, and the choice is **not** "keep digging":

- Enough to close → close with the evidence recorded.
- Enough to escalate → escalate.
- **Neither → escalate anyway.** An alert that resists a full time-box is
  itself a signal. Ambiguity is not a reason to keep it in your queue; it is a
  reason to give it more resources than you have.

Escalate immediately, without finishing triage, on any of: confirmed execution
on a crown-jewel asset, credential access on a domain controller or identity
provider, evidence of lateral movement, security tooling being disabled, or
anything touching backup infrastructure. These are too expensive to be wrong
about slowly.

## A Closed Alert Must Be Evidence

Record what you checked, what you found, and what would change your mind. A
disposition with no reasoning is unreviewable, and the alert that preceded a
breach is always reviewed.

The dangerous phrasing is *"no evidence of compromise found"* where the honest
statement is *"the telemetry that would show compromise is not collected."*
The first closes the question; the second is a finding about a visibility gap
and belongs to `engineering-detections`.

Every disposition also carries information back to detection engineering:
false positives are logic defects, repeated benign true positives are missing
authorized-context filters, and a rule producing only noise for months should
be measured and removed rather than endured.

## Rationalizations to Reject

- *"The tool rated it critical, so it is serious."* Severity was set by the
  rule author against a generic environment. Your base rate is local.
- *"It has fired a hundred times before and always been nothing."* Prior
  benignity is evidence, not proof — and an attacker who knows the rule is
  ignored will use exactly that technique. Check *this* instance's specifics.
- *"The user said it was them."* Confirms someone used the account, not that
  the account was not also used by someone else. Compromised users answer the
  phone. Corroborate against telemetry.
- *"It stopped on its own, so it resolved."* Activity ceasing is equally
  consistent with the operator finishing, moving on, or going quiet. Nothing
  self-resolves in security.
- *"I could not find anything, so it is a false positive."* Absence of evidence
  in telemetry you did not check, or that is not collected, is not a false
  positive. Say which you mean.
- *"It is a known false positive."* Then it should have been tuned or filtered.
  If it is still firing, either the tuning is missing or it is actually a
  benign true positive being mislabelled — both are actions, not dispositions.
- *"I will keep digging until I am certain."* Certainty is not on the menu, and
  the queue is still arriving. Time-box, then escalate on ambiguity.
- *"Escalating something benign makes me look careless."* Escalating ambiguity
  is the system working. Closing ambiguity silently is the failure the post-
  incident review will find.

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

- `responding-to-incidents` — where a true positive goes next
- `engineering-detections` — where false positives and tuning gaps go back to
- `hunting-threats` — the hypothesis-driven counterpart to queue-driven triage
- `investigating-windows-endpoints` — deep host analysis once triage escalates
