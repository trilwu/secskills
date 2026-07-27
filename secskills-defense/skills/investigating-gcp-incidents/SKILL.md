---
name: investigating-gcp-incidents
description: Investigate a security incident in Google Cloud — establishing what audit logging exists before trusting a gap, reconstructing activity from Cloud Audit Logs, triaging service-account and OAuth abuse, following Security Command Center findings, and scoping IAM and resource changes. Use when responding to a suspected GCP compromise, investigating a leaked service-account key, working a Security Command Center or Event Threat Detection alert, or reconstructing what a principal did across a GCP organization.
verified: 2026-07-27
---

# Investigating GCP Incidents

The completeness of a GCP investigation is decided before the incident, by
which audit logs were enabled. The single most damaging mistake is reading an
empty query result as "nothing happened" when the real answer is "that log
category was never turned on." Establish visibility first; conclude second.

GCP's audit model is not AWS's and not Azure's. Two categories are always on
and two are mostly off, and knowing which is which is the difference between a
scoped investigation and a false all-clear.

## When to Use

- Responding to a suspected compromise in a GCP project or organization
- Investigating a leaked or abused service-account key
- Working a Security Command Center, Event Threat Detection, or Chronicle alert
- Reconstructing a principal's activity across projects
- Scoping IAM policy or resource changes after a suspected privilege escalation

## When NOT to Use

- **The incident is in AWS** — use `investigating-aws-incidents`; in Azure or
  Microsoft 365 / Entra — use `investigating-azure-incidents` or
  `investigating-m365-entra`
- **Attacking GCP rather than investigating it** — use
  `exploiting-cloud-platforms`
- **A GKE cluster compromise specifically** — start here for the cloud-plane
  view, then use `defending-kubernetes` for the cluster-plane
- **Deciding whether an alert is even an incident** — use
  `triaging-security-alerts` first

## Establish Visibility Before You Conclude

GCP Cloud Audit Logs come in four streams, and their defaults are the whole
game:

| Stream | Default | Can disable? | What it captures |
| --- | --- | --- | --- |
| **Admin Activity** | Always on | No — written even if the Logging API is disabled | Config and metadata writes: IAM changes, resource create/delete |
| **System Event** | Always on | No | Google-initiated actions on your resources |
| **Data Access** | **Off** (except BigQuery) | Yes | Reads and data-plane access — who read the bucket, the secret, the dataset |
| **Policy Denied** | On | No (can exclude from storage) | Access blocked by policy — VPC-SC, org policy |

The consequence you must internalize: **Data Access logging is off by default
everywhere except BigQuery.** So "did the attacker read the secret / download
the bucket / exfiltrate the dataset?" is usually *unanswerable* from logs
unless Data Access logging was enabled in advance. Do not report "no
exfiltration occurred" — report "Data Access logging was not enabled, so
read activity cannot be confirmed or ruled out." Those are different findings,
and only one is honest.

Retention also differs by stream. Admin Activity and System Event land in the
`_Required` bucket — **400 days, not configurable**. Data Access and Policy
Denied land in `_Default` — **30 days** unless someone extended it or routed a
sink to longer storage. Check the retention before assuming history exists.

```bash
# What audit config is actually in effect at the org / project level
gcloud organizations get-iam-policy ORG_ID --format=json | jq '.auditConfigs'
gcloud projects get-iam-policy PROJECT_ID --format=json | jq '.auditConfigs'
```

## Reconstructing Activity

```bash
# Everything a principal did (Admin Activity is always present)
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="attacker@example.com"' \
  --project=PROJECT_ID --freshness=30d --format=json

# IAM policy changes — the escalation signal
gcloud logging read \
  'protoPayload.methodName:"SetIamPolicy"' --freshness=30d --format=json

# Service-account key creation — persistence
gcloud logging read \
  'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' \
  --freshness=30d --format=json
```

Read the request fields, not just the method name. `authenticationInfo`
carries the principal and, critically, whether a call was made *as* a service
account via impersonation. `requestMetadata.callerIp` and `callerSuppliedUserAgent`
locate the source; a `gcloud` user agent from an unexpected ASN on a service
account is a strong signal.

## Service-Account and OAuth Abuse

Service accounts are the center of most GCP incidents, because they hold
durable credentials and are routinely over-privileged.

- **Impersonation chains.** `iam.serviceAccounts.getAccessToken` and
  `...signJwt`/`...signBlob` let one principal act as another. Trace the chain:
  who impersonated what, and does the terminal identity hold more than the
  origin? This is GCP's primary lateral-movement and escalation primitive.
- **Key creation** is persistence — a user-managed key survives a password
  reset and an MFA change. Every `CreateServiceAccountKey` on a privileged SA
  during the incident window is a finding.
- **OAuth grants and the Workspace boundary.** A domain-wide-delegation grant
  lets a GCP service account act across Google Workspace; that crosses into
  `investigating-m365-entra`-style identity territory and is easy to miss from
  a pure-GCP view.

## Follow Security Command Center, Don't Restart From Zero

If Security Command Center is enabled, Event Threat Detection has likely
already correlated some of this — anomalous IAM grants, service-account key
abuse, and exfiltration patterns surface as findings. Start from SCC findings
to seed the timeline, then corroborate each against the raw audit logs rather
than trusting the finding alone. SCC in the Standard tier is far thinner than
Premium/Enterprise; confirm which tier is licensed before assuming a detection
would have fired.

## Rationalizations to Reject

- *"The logs show no data access, so nothing was exfiltrated."* Data Access
  logging is off by default. Absence of the log is absence of the *logging*,
  not absence of the access. Report the visibility gap.
- *"Admin Activity is empty for that window, so the account was idle."* Check
  the principal spelling and the project — activity is logged in the project
  whose resource was touched, which may not be the one you are querying.
- *"It's only 30 days back."* That is the `_Default` bucket. Admin Activity is
  400 days; if the relevant action was an IAM or resource change, the history
  is longer than you think.
- *"The service account made the call, so it was legitimate automation."*
  Service accounts are exactly what attackers impersonate. Check whether the
  call came via `getAccessToken`/impersonation and from what source.
- *"SCC didn't flag it, so it didn't happen."* Standard-tier SCC detects a
  fraction of what Premium does, and Data Access-dependent detections need the
  logs enabled. A quiet SCC is not an all-clear.

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

- `investigating-aws-incidents`, `investigating-azure-incidents` — the same
  discipline in the other two clouds
- `defending-kubernetes` — the cluster-plane view when the incident is in GKE
- `responding-to-incidents` — the overall IR framing this feeds
- `hardening-cloud-posture` — enabling the Data Access logging whose absence
  this skill keeps running into
