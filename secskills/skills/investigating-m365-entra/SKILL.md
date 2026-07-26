---
name: investigating-m365-entra
description: Investigate security incidents in Microsoft 365 and Entra ID (Azure AD) -- search the Unified Audit Log, correlate sign-in and audit events, trace illicit OAuth consent grants, analyze mailbox rule manipulation, and contain compromised identities. Use when responding to a BEC incident, investigating Entra ID compromise, analyzing suspicious OAuth app permissions, tracing mail forwarding abuse, or reviewing Azure AD sign-in anomalies.
---

# Investigating M365 and Entra ID

M365/Entra investigations differ from on-premises DFIR -- there are no disk
images, no memory dumps, and no event logs you can collect yourself. Everything
comes from API queries against Microsoft's log stores, several of which require
E5 licensing or advanced audit to retain what you need. Knowing which logs
exist, which ones are missing, and how long they last is half the investigation.

## When to Use

- Business email compromise (BEC) -- unauthorized mailbox access, forwarding, or impersonation
- Entra ID account compromise -- suspicious sign-ins, token replay, credential stuffing
- Suspicious OAuth consent grants -- third-party apps with excessive permissions
- Mailbox rule manipulation -- inbox rules hiding attacker communications or forwarding mail
- Azure AD sign-in anomalies -- impossible travel, legacy auth, anonymizer networks
- Conditional Access or MFA tampering -- policy changes, MFA fatigue attacks

## When NOT to Use

- **Broader incident response methodology** -- use `responding-to-incidents`
- **Offensive testing of Entra ID** -- use `attacking-entra-id`
- **Cloud infrastructure beyond M365 (AWS, GCP, Azure IaaS)** -- use `exploiting-cloud-platforms`
- **Building detection rules from findings** -- use `engineering-detections`

## Log Landscape and Retention

Before you query anything, establish what you have and how far back it goes.
Missing logs are a finding, not a reason to skip the question.

| Log source | Retention (default) | License gate | Key operations |
| --- | --- | --- | --- |
| Unified Audit Log (UAL) | 180d (E5), 90d (E3) | MailItemsAccessed requires E5 | MailItemsAccessed, New-InboxRule, Set-Mailbox, consent grants |
| Entra ID sign-in logs | 30d | Export to Log Analytics for longer | Sign-in events, CA evaluation, MFA results |
| Entra ID audit logs | 30d | None | Role assignments, app registrations, credential changes |
| Identity Protection | 30d | Requires P2 | Risky sign-ins, risk detections |
| Defender for Cloud Apps | 180d | Requires MDCA license | Activity log, OAuth app inventory |
| Mailbox audit log | 90d (on by default) | MailItemsAccessed requires E5 | Mail access, send-as, delegate ops |

If the tenant is E3-only, you have 90 days of UAL and no MailItemsAccessed.
State that gap explicitly. Check SIEM or Log Analytics for extended retention.

## Unified Audit Log (UAL)

The UAL is the single richest data source. Every investigation starts here.

```powershell
Connect-ExchangeOnline -UserPrincipalName admin@tenant.onmicrosoft.com

# Basic search -- always constrain by date and user
Search-UnifiedAuditLog -StartDate "2026-07-01" -EndDate "2026-07-20" `
  -UserIds compromised@contoso.com -ResultSize 5000

# Search specific operations
Search-UnifiedAuditLog -StartDate "2026-07-01" -EndDate "2026-07-20" `
  -Operations "New-InboxRule","Set-InboxRule","Set-Mailbox","Add-MailboxPermission" `
  -ResultSize 5000

# MailItemsAccessed (E5 only)
Search-UnifiedAuditLog -StartDate "2026-07-01" -EndDate "2026-07-20" `
  -Operations MailItemsAccessed -UserIds compromised@contoso.com -ResultSize 5000

# Export -- AuditData field is JSON, expand it
Search-UnifiedAuditLog -StartDate "2026-07-01" -EndDate "2026-07-20" `
  -UserIds compromised@contoso.com -ResultSize 5000 |
  Select-Object CreationDate, UserIds, Operations,
    @{N='AuditData';E={$_.AuditData | ConvertFrom-Json | ConvertTo-Json -Depth 10}} |
  Export-Csv -Path .\ual_export.csv -NoTypeInformation
```

### Key UAL operations

| Operation | Significance |
| --- | --- |
| MailItemsAccessed | Bind = single item read, Sync = bulk download. Bulk sync is the BEC exfiltration indicator. |
| New-InboxRule / Set-InboxRule | Rules hiding replies or forwarding. Check for keyword targets: "invoice", "payment", "security". |
| Set-Mailbox | ForwardingSMTPAddress or ForwardingAddress changed -- silent external forwarding. |
| Add-MailboxPermission | FullAccess or SendAs delegation -- persistence. |
| Consent to application | OAuth grant. AuditData contains the permissions. |
| Add service principal credentials | New secret/certificate on an app registration. |
| HardDelete / SoftDelete | Evidence destruction -- attacker deleting sent items. |

The UAL caps at 50,000 results per query. Narrow the date range if you hit it.

## Entra ID Sign-In Analysis

Query sign-in logs and look for:

- **Impossible travel** -- distant locations within an impossible timeframe
- **Anonymous IPs** -- Tor exits, VPN services, known anonymizers
- **Legacy auth** -- IMAP, POP3, SMTP AUTH bypass MFA unless CA blocks them
- **Token replay** -- same correlation ID from different source IPs
- **Anomalous user agents** -- Python requests, PowerShell hitting OWA or Graph

```kusto
// Sign-ins from the compromised account
SigninLogs
| where UserPrincipalName == "compromised@contoso.com"
| where TimeGenerated > ago(30d)
| project TimeGenerated, AppDisplayName, IPAddress, Location,
    ClientAppUsed, ResultType, AuthenticationRequirement, MfaDetail, RiskState
| order by TimeGenerated asc

// Legacy auth sign-ins that bypass MFA
SigninLogs
| where ClientAppUsed in ("IMAP4", "POP3", "SMTP", "Exchange ActiveSync",
    "MAPI Over HTTP", "Outlook Anywhere", "Exchange Web Services")
| where ResultType == 0
| summarize count() by UserPrincipalName, ClientAppUsed, IPAddress
```

### MFA analysis

- **ResultType 50074** -- MFA required, not completed
- **ResultType 50076** -- MFA completed (attacker had the factor or used MFA fatigue)
- **AuthenticationRequirement = singleFactorAuthentication** -- MFA not required (CA gap)
- Check `MfaDetail` -- push acceptance after repeated prompts = MFA fatigue

## OAuth and Consent Grant Investigation

Illicit consent grants are the most-missed persistence in M365 compromise.

```powershell
Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All"

# Delegated permission grants -- look for Mail.Read, Files.ReadWrite, etc.
Get-MgOauth2PermissionGrant -All | Where-Object {
    $_.Scope -match "Mail.Read|Mail.ReadWrite|Files.ReadWrite|User.Read.All"
} | Format-Table ClientId, ConsentType, Scope, PrincipalId

# Application permission assignments
Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue |
    Select-Object @{N='AppName';E={$sp.DisplayName}}, @{N='AppId';E={$sp.AppId}},
                  PrincipalDisplayName, @{N='Created';E={$_.CreatedDateTime}}
}
```

| Permission | Risk |
| --- | --- |
| Mail.Read / Mail.ReadWrite | Email exfiltration. Suspicious on unknown apps. |
| Files.ReadWrite.All | Full SharePoint/OneDrive access. |
| Directory.ReadWrite.All | Can modify users, groups, roles. |
| full_access_as_app | Exchange app-level mailbox access -- almost never legitimate for third parties. |

Distinguish delegated consent (one user's data) from admin consent (tenant-wide).
Admin consent to a malicious app exposes every user.

## Mailbox Rule Forensics

Inbox rules persist after password resets. Always check them.

```powershell
# Inbox rules
Get-InboxRule -Mailbox compromised@contoso.com |
  Select-Object Name, Enabled, MoveToFolder, DeleteMessage, ForwardTo,
    RedirectTo, MarkAsRead | Format-List

# Mailbox-level forwarding
Get-Mailbox -Identity compromised@contoso.com |
  Select-Object ForwardingSMTPAddress, ForwardingAddress, DeliverToMailboxAndForward

# All mailboxes with external forwarding
Get-Mailbox -ResultSize Unlimited |
  Where-Object { $_.ForwardingSMTPAddress -ne $null } |
  Select-Object UserPrincipalName, ForwardingSMTPAddress

# Transport rules
Get-TransportRule | Where-Object { $_.RedirectMessageTo -or $_.BlindCopyTo } |
  Select-Object Name, State, RedirectMessageTo, BlindCopyTo

# Delegate access
Get-MailboxPermission -Identity compromised@contoso.com |
  Where-Object { $_.User -ne "NT AUTHORITY\SELF" -and -not $_.IsInherited }
```

Red flags: rules targeting keywords ("security", "password", "MFA"), rules
deleting or moving to RSS Feeds / Conversation History, blank-named rules,
forwarding to free email providers, rules created after the first suspicious
sign-in.

## eDiscovery and Content Search

```powershell
Connect-IPPSSession -UserPrincipalName admin@tenant.onmicrosoft.com

# Preserve mailbox content -- do this early
Set-Mailbox -Identity compromised@contoso.com -LitigationHoldEnabled $true

# Search outbound mail from compromised account
New-ComplianceSearch -Name "IR-2026-042 Outbound" `
  -ExchangeLocation compromised@contoso.com `
  -ContentMatchQuery "sent>=2026-07-01 AND sent<=2026-07-20"
Start-ComplianceSearch -Identity "IR-2026-042 Outbound"
```

Place litigation holds before retention policies or the attacker can purge evidence.

## Azure AD Audit Log Analysis

```kusto
// Role assignments
AuditLogs
| where OperationName == "Add member to role"
| extend TargetUser = tostring(TargetResources[0].userPrincipalName),
         RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| project TimeGenerated, InitiatedBy, TargetUser, RoleName

// Service principal credential changes (persistence)
AuditLogs
| where OperationName in ("Add service principal credentials",
    "Update application - Certificates and secrets management")
| project TimeGenerated, InitiatedBy, TargetResources

// Conditional Access policy changes
AuditLogs
| where OperationName has "conditional access"
| project TimeGenerated, OperationName, InitiatedBy, Result

// MFA method changes (attacker registering their own factor)
AuditLogs
| where OperationName in ("User registered security info",
    "Admin registered security info", "User deleted security info")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

Attackers with Application Admin or Global Admin can add credentials to
existing app registrations for persistent, MFA-independent access:

```powershell
Get-MgApplication -All | ForEach-Object {
    $app = $_
    $app.PasswordCredentials + $app.KeyCredentials | Where-Object {
        $_.StartDateTime -gt (Get-Date).AddDays(-30)
    } | Select-Object @{N='App';E={$app.DisplayName}}, @{N='AppId';E={$app.AppId}},
                      StartDateTime, EndDateTime
}
```

## Timeline Construction

Correlate across the three primary log sources:

```
Sign-in logs  -->  When and where the attacker authenticated
Audit logs    -->  Configuration changes they made
UAL           -->  Data they accessed or modified
```

1. Anchor on the earliest suspicious sign-in
2. Pull sign-in, UAL, and audit events for that user +/- 7 days
3. Merge into a single UTC timeline
4. Look for the pattern: sign-in, reconnaissance, persistence (rule/forwarding/OAuth), action on objectives

```
UTC Timestamp        | Source  | Event                                    | Detail
2026-07-12 08:41:22  | SignIn  | Sign-in from 198.51.x.x                  | Nigeria, no MFA
2026-07-12 08:42:05  | UAL     | MailItemsAccessed (Sync)                 | 847 items via Graph
2026-07-12 08:43:18  | UAL     | New-InboxRule "."                        | Delete "security alert"
2026-07-12 08:44:01  | UAL     | Set-Mailbox                              | ForwardingSMTPAddress set
2026-07-12 08:45:33  | UAL     | Consent to application                   | Mail.Read, Mail.Send
2026-07-12 09:12:44  | UAL     | Send (SendAs)                            | Invoice redirect to vendor
```

## Containment

Execute simultaneously once scoping is complete. Partial containment alerts the attacker.

```powershell
# Revoke sessions and reset credentials
Revoke-MgUserSignInSession -UserId compromised@contoso.com
Update-MgUser -UserId compromised@contoso.com -PasswordProfile @{
    Password = (New-Guid).Guid + "!Aa1"; ForceChangePasswordNextSignIn = $true }

# Disable account if active compromise is ongoing
Update-MgUser -UserId compromised@contoso.com -AccountEnabled:$false

# Remove attacker inbox rules
Get-InboxRule -Mailbox compromised@contoso.com |
  Where-Object { $_.Name -match "^\.$|^$" -or $_.DeleteMessage -eq $true } |
  Remove-InboxRule -Confirm:$false

# Remove forwarding
Set-Mailbox -Identity compromised@contoso.com `
  -ForwardingSMTPAddress $null -ForwardingAddress $null `
  -DeliverToMailboxAndForward $false

# Remove unauthorized delegate access
Get-MailboxPermission -Identity compromised@contoso.com |
  Where-Object { $_.User -ne "NT AUTHORITY\SELF" -and -not $_.IsInherited } |
  ForEach-Object { Remove-MailboxPermission -Identity compromised@contoso.com `
    -User $_.User -AccessRights $_.AccessRights -Confirm:$false }

# Block malicious OAuth app
$sp = Get-MgServicePrincipal -Filter "appId eq '<malicious-app-id>'"
Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AccountEnabled:$false
Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)'" |
  Remove-MgOauth2PermissionGrant
```

Session revocation alone is insufficient -- tokens may remain valid up to one
hour. Disable the account for immediate lockout. After containment, verify: no
forwarding remains, no unknown delegates, no unknown OAuth grants, no
attacker-registered MFA methods, no service principal credentials from the
compromise window.

## Rationalizations to Reject

- *"We reset the password, so the account is secure."* Refresh tokens, OAuth
  grants, inbox rules, forwarding, and delegate access all survive a password
  reset. Revoke sessions and audit every persistence mechanism.
- *"We only have E3, so we cannot investigate mail access."* MailItemsAccessed
  is unavailable, but sign-in logs, UAL operations, inbox rules, and forwarding
  still exist. State the gap and work with what you have.
- *"The sign-in was from a VPN, so it is probably the user."* Correlate the
  exit IP, user agent, and timing against established patterns. Attackers use
  VPNs too.
- *"No alerts fired in Defender, so there is no compromise."* Defender requires
  the right license tier and policy config. Absence of alerts is not evidence
  of absence.
- *"The OAuth app only has delegated permissions."* Delegated permissions with
  a valid refresh token give persistent access without needing the password again.
- *"We blocked the IP, so the attacker is locked out."* Attackers rotate IPs.
  Revoke the tokens and credentials, not just the network path.
- *"Logs only go back 30 days, so the compromise started within that window."*
  That is your visibility limit, not the attacker's timeline. Document the
  limitation and check SIEM for extended retention.

## References

- `responding-to-incidents` -- broader IR methodology and evidence handling
- `attacking-entra-id` -- offensive Entra ID techniques, useful for understanding attacker methods
- `exploiting-cloud-platforms` -- cloud infrastructure attacks beyond M365
- `engineering-detections` -- building detection rules from investigation findings
- `hunting-threats` -- proactive hunting in M365 and Entra ID telemetry
