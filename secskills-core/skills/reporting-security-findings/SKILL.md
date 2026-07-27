---
name: reporting-security-findings
description: Write security findings and assessment reports — severity scoring with CVSS and business impact, reproducible proof of concept, remediation guidance, executive summaries, and coordinated disclosure. Use when writing up a vulnerability, producing a pentest or audit report, triaging a bug bounty submission, or preparing a disclosure timeline.
---

# Reporting Security Findings

The report is the product. Findings that are not understood are not fixed, and
findings that cannot be reproduced are disputed. Most of the value an
assessment creates is destroyed or preserved in the write-up.

## When to Use

- Writing up a single vulnerability
- Producing a penetration test, code audit, or red team report
- Submitting to a bug bounty program or triaging inbound submissions
- Scoring severity and arguing priority with an engineering team
- Planning coordinated disclosure for an unpatched issue

## When NOT to Use

- **Finding the bug** — use the relevant testing or audit skill first
- **Incident narratives and postmortems** — use `responding-to-incidents`
- **Compliance-framework mapping as the primary goal** — different document,
  different audience

## Anatomy of a Finding

Every finding answers five questions, in this order:

```markdown
### F-03  Tenant isolation bypass in report export     [High]

**Summary**
An authenticated user of any tenant can export reports belonging to other
tenants by supplying an arbitrary report ID to `GET /api/v2/reports/{id}/export`.

**Impact**
Full read access to other customers' report data, including the financial
figures and contact records those reports contain. Any customer account —
including a self-service trial — is sufficient. This is a cross-tenant
confidentiality breach with likely contractual and regulatory consequences.

**Affected**
`api/handlers/reports.go:214` (`handleExport`), deployed in production as of
commit `a1b2c3d`. Reproduced on staging 2026-07-24 14:02 UTC.

**Reproduction**
1. Authenticate as `trial-user@tenant-a` and obtain a session token.
2. Note your own report ID from `GET /api/v2/reports` (e.g. `1041`).
3. Request a neighbouring ID:
   curl -H "Authorization: Bearer $TOKEN" \
        https://staging.example.com/api/v2/reports/1042/export -o out.csv
4. `out.csv` contains tenant B's data. Confirmed with IDs 1042, 1043, 1055.

**Root cause**
The handler looks the report up by primary key and checks only that the
session is valid. The tenant scope present on the list endpoint
(`WHERE tenant_id = ?`) is absent from the export query.

**Remediation**
Add the tenant predicate to the export lookup, and enforce it at the data
access layer rather than per handler so new endpoints inherit it:
    SELECT ... FROM reports WHERE id = ? AND tenant_id = ?
Then audit the remaining 14 handlers that call `findByID` without a scope —
listed in Appendix B.

**References**
CWE-639, OWASP API1:2023 Broken Object Level Authorization
```

Rules that make findings act-on-able:

- **One finding per issue.** Bundling ten IDORs into "authorization issues"
  guarantees partial fixes.
- **Exact locations.** File, line, endpoint, commit, and the environment where
  you reproduced it.
- **Reproduction someone else can run** without asking you a question. Include
  the setup, the request, and the observed result — not just the payload.
- **Root cause, not just symptom.** The fix for a symptom leaves the class.
- **Remediation that names the change.** "Validate input" is not remediation.
- **Variants listed.** If you found one instance and suspect more, say what you
  checked and what you did not.

## Severity

CVSS is the common currency, but it scores a vulnerability in the abstract.
Score with CVSS, then state business impact separately — engineering
prioritizes on the second.

```
CVSS 4.0 base vector example:
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N   → 6.9 Medium
```

Then adjust for reality and say why:

| Factor | Raises priority | Lowers priority |
| --- | --- | --- |
| Exposure | Internet-facing, unauthenticated | Internal only, requires admin |
| Data | Regulated, customer, credentials | Synthetic, public |
| Exploit maturity | Public exploit, active exploitation | Theoretical, complex chain |
| Compensating controls | None | WAF rule, network segmentation, monitoring |
| Blast radius | Cross-tenant, whole fleet | Single account, single record |

A Medium CVSS that breaks tenant isolation for a SaaS product is a P1
regardless of the number. Say that explicitly rather than letting the score
argue for you. Conversely, do not inflate scores: a report where everything is
Critical gets triaged by ignoring it.

**Chained findings**: report the components individually *and* report the chain
as its own finding with the chain's severity. The chain is what an attacker
does; the components are what engineering fixes.

## Proof of Concept

Scale the PoC to what proves the point:

- **Enough to prove control of the sink.** `id=1042` returning another tenant's
  row proves the bug. Dumping the full database does not prove it harder.
- **Non-destructive by default.** Do not modify or delete data to demonstrate
  write access; write a benign marker to a record you own, or demonstrate the
  authorization decision without the effect.
- **Redact real data.** If your evidence contains customer records, redact them
  in the report and store the raw evidence separately with access controls.
- **State what you did.** If you created accounts, uploaded files, or left
  artifacts, list them so they can be cleaned up.

For memory-safety and exploitation findings, a crash with a controlled
instruction pointer plus an analysis of exploitability is usually the right
depth. A weaponized exploit belongs in the report only when the engagement
explicitly calls for it.

## The Report

```
1. Executive summary        — 1 page, no jargon, answers "how bad and what now"
2. Scope and methodology    — what was tested, how, and with what access
3. Coverage and limitations — what was NOT tested, and why
4. Findings                 — ordered by severity, each self-contained
5. Strategic recommendations— themes across findings, not per-finding fixes
6. Appendices               — tooling, raw output, evidence index, retest results
```

**The executive summary is written for someone who will read only it.** Three
things: the overall risk position in a sentence, the two or three findings that
matter, and what decision is being asked for. No CVSS vectors, no tool names,
no "we ran Nessus."

**Coverage and limitations is the section that protects everyone.** State the
time box, the accounts and environments you had, the components you could not
reach, and the testing you were asked not to do. A report silent on limitations
implies coverage it did not have, and that silence is what turns a missed bug
into a dispute.

**Strategic recommendations** are where an assessment earns repeat work: the
themes. "Authorization is enforced per handler rather than at the data layer;
9 of 14 findings share this root cause." That sentence is worth more than the
nine findings.

## Writing for the Audience

| Reader | Wants | Give them |
| --- | --- | --- |
| Executive | Risk and decision | One page, plain language, business consequence |
| Engineering manager | Prioritization and effort | Severity, root cause, scope of the fix |
| Engineer | To fix it today | Exact location, reproduction, concrete change |
| Compliance/audit | Evidence and mapping | Methodology, coverage statement, framework refs |

Write the finding for the engineer, and the summary for the executive. Do not
average the two into prose that serves neither.

Tone: describe the defect, not the developer. "The export handler omits the
tenant predicate" — not "the developer forgot." Reports circulate, and an
accusatory report makes the next engagement harder.

## Disclosure

For findings in software you do not own:

```
Day 0     Report privately: security.txt, /security, GitHub advisory, CERT
Day 0-7   Acknowledge receipt; agree a timeline
Day 45    Check in; offer help reproducing
Day 90    Standard public disclosure deadline (adjust for severity and
          exploitation in the wild — actively exploited issues warrant faster
          public warning; complex fixes may warrant an extension you agree to)
```

- Give a specific deadline at first contact, and honour it.
- Request a CVE when the issue affects released software with other users.
- Do not publish exploit code before a fix is broadly available; describe
  impact and mitigation instead.
- If the vendor is unresponsive, escalate to a CERT/CSIRT coordinator rather
  than going straight to publication.
- Never test beyond the authorized scope to "improve the report," and never
  use a finding as leverage. Both convert a research contribution into a legal
  problem.

For bug bounty submissions, read the program's scope and rules first, report
one issue per submission, and include the impact statement the triager needs
to justify the payout internally.

## Rationalizations to Reject

- *"They'll understand what I mean."* They will not, and they will not ask —
  they will downgrade it.
- *"I'll write it up later."* Reproduction details decay within hours.
- *"It's obviously Critical."* Then it is easy to justify. Justify it.
- *"Everything is High so they take it seriously."* Inflated severity is how a
  report stops being read.
- *"I couldn't fully exploit it, so I'll leave it out."* Report it with the
  evidence you have and state the uncertainty. Silent omission is worse.
- *"The client won't like the limitations section."* They will like it less
  after a breach in an area the report implied was covered.
- *"No findings means a bad report."* A report with honest coverage and no
  findings is a valid result. Say what you tested and how deeply.

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

## References

- `auditing-code-for-vulnerabilities` — the audit-side deliverable format
- `responding-to-incidents` — incident narratives and postmortems
- CVSS 4.0 specification; EPSS for exploitation likelihood; CWE for classification
- ISO/IEC 29147 (vulnerability disclosure) and 30111 (handling)
