---
name: investigating-azure-incidents
description: Investigate security incidents in Microsoft Azure (resource and subscription control plane) -- reconstruct attacker activity from the Azure Activity Log and resource/data-plane diagnostic logs, anchor the investigation on the identity that made the calls (a user, service principal, or managed identity), trace privilege escalation through role assignments, hunt managed-identity token abuse and VM run-command code execution, and detect storage or Key Vault data theft while correlating back to Entra sign-in logs. Use when responding to a suspected Azure resource compromise, anomalous Azure Activity Log entries, a Microsoft Defender for Cloud alert, managed-identity or service-principal abuse, a crypto-mining VM, or storage-account exfiltration.
---

# Investigating Azure Incidents

In Azure the control plane logs almost everything through Azure Resource
Manager, so an incident is reconstructed from the Activity Log and the
resource/data-plane logs, anchored on the identity that made the calls -- a
user, a service principal, or a managed identity. The recurring trap is that
identity lives in Entra while the damage lives in the subscription: you must
correlate across both planes, because the Activity Log tells you *what* was done
to a resource but the Entra sign-in log tells you *who* held the token and from
where.

## When to Use

- Suspected Azure resource compromise -- a subscription, resource group, or VM behaving as though someone else controls it
- Anomalous Azure Activity Log entries -- writes from unfamiliar callers, IPs, or regions, or an `AccessDenied` storm that looks like enumeration
- A Microsoft Defender for Cloud alert -- crypto-mining, anomalous resource deployment, suspicious sign-in, or IMDS token theft
- Managed-identity or service-principal abuse -- tokens minted for an app or VM being used from somewhere they should never appear
- A crypto-mining VM -- an unexpected spend spike, GPU/large SKUs, or new deployments in regions you do not operate in
- Storage-account or Key Vault exfiltration -- key regeneration, SAS-token minting, public-access changes, disk-snapshot sharing, or secret dumps

## When NOT to Use

- **The compromise is Entra identity / M365 mailbox, not Azure resources** (though you will often need both) -- use `investigating-m365-entra`
- **The incident is in AWS** -- use `investigating-aws-incidents`
- **You are the attacker against the tenant, not the responder** -- use `attacking-entra-id`
- **The pivot is specifically into AKS / Kubernetes** -- use `attacking-eks-gke-aks`
- **The general IR process and host-level response** -- use `responding-to-incidents`

## Log Sources and Where They Live

Establish what you have before you query. Missing logs are a finding, not a
reason to skip the question.

| Source | Scope | Retention (default) | What it holds |
| --- | --- | --- | --- |
| Azure Activity Log | Subscription control plane | 90 days unless exported | Every ARM write/action/delete: `roleAssignments`, `runCommand`, `listKeys`, deployments |
| Resource / diagnostic logs | Per-resource data plane | None until enabled | Blob reads, Key Vault `SecretGet`, NSG flow -- only if a diagnostic setting ships them to a workspace |
| Log Analytics workspace | Wherever logs are shipped | Workspace-configured | `AzureActivity`, `AzureDiagnostics`, `StorageBlobLogs`, `KeyVaultData` tables |
| Entra sign-in / audit logs | Tenant identity plane | 30 days (export for more) | Who authenticated the SP/MI, from where, CA/MFA context, credential adds |
| Microsoft Sentinel | Whatever it ingests | Per-table | Correlated hunting across all of the above, incidents, watchlists |

**The trap:** the Activity Log is a *control-plane* record. Data-plane
operations -- reading a blob, fetching a Key Vault secret, querying a Cosmos DB
-- are **not** in the Activity Log at all. They exist only if a diagnostic
setting was configured on that resource *before* the incident. Absence in the
Activity Log is never evidence that data was untouched (see Rationalizations).

Confirm what is actually being logged before you trust a gap: `az monitor
diagnostic-settings subscription list` (is the Activity Log exported beyond 90
days?) and `az monitor diagnostic-settings list --resource <id>` (does this
storage account / vault ship data-plane logs anywhere?).

## First-Hour Triage

Three moves, in order: scope the caller identity, pull its recent activity,
preserve before you contain.

**Scope the caller identity.** Resolve the report -- a Defender alert, a
billing spike, a suspicious deployment -- to the identity in the `caller` /
`identity` fields of the Activity Log. That principal (a UPN, or a service
principal / managed identity object ID) is the anchor for everything else.

```bash
# Everything a specific caller did across the subscription control plane
az monitor activity-log list --caller attacker@contoso.com \
  --start-time 2026-07-01T00:00:00Z -o json

# Who holds what right now -- role assignments are the escalation surface
az role assignment list --all --include-inherited \
  --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator']" -o table
```

**Pull recent activity from KQL** if a Log Analytics workspace exists -- it is
faster and richer than the CLI once you are past the first look:

```kusto
AzureActivity
| where TimeGenerated > ago(7d)
| where Caller == "attacker@contoso.com"
| project TimeGenerated, OperationNameValue, ActivityStatusValue,
    CallerIpAddress, ResourceProviderValue, ResourceId, CorrelationId
| order by TimeGenerated asc
```

**Preserve, then contain.** An attacker who sees a role assignment revoked
mid-operation will burn persistence you have not found. For anything but active,
ongoing damage: snapshot disks, export the relevant logs, map persistence, then
contain everything at once. Live mining or active exfil is the exception -- stop
the damage and accept the trade.

## Activity Log Deep-Dive (KQL)

The `AzureActivity` table is the authoritative control-plane record. Learn its
fields:

- **`OperationNameValue`** -- the ARM operation, e.g.
  `Microsoft.Authorization/roleAssignments/write`. This is what you hunt on.
- **`Caller`** -- the UPN or object ID that made the call.
- **`CallerIpAddress`** -- external IPs on a managed identity that should only
  call from inside Azure are the IMDS-theft signature (below).
- **`ResourceProviderValue`** -- `Microsoft.Compute`, `Microsoft.Storage`,
  `Microsoft.KeyVault`, `Microsoft.Authorization`.
- **`ActivityStatusValue`** -- a run of `Failure` (often `AuthorizationFailed`)
  is enumeration: the attacker mapping what the stolen principal can reach.
- **`CorrelationId`** -- ties the sub-operations of one logical action together;
  pivot on it to expand a single suspicious event into its full sequence.

```kusto
// Enumeration storm -- authorization failures by operation
AzureActivity
| where TimeGenerated > ago(7d)
| where ActivityStatusValue == "Failure"
| summarize n = count() by Caller, OperationNameValue, CallerIpAddress
| order by n desc

// Expand one event's full correlated sequence
AzureActivity
| where CorrelationId == "<correlation-id>"
| project TimeGenerated, OperationNameValue, ActivityStatusValue, ResourceId
| order by TimeGenerated asc
```

## Canonical Attacker Operations to Hunt

Grep the timeline for these `OperationNameValue` patterns -- they are the shape
of nearly every Azure intrusion.

- **Privilege escalation via role assignment** --
  `Microsoft.Authorization/roleAssignments/write` granting **Owner**,
  **Contributor**, or **User Access Administrator** (UAA can grant itself
  anything). Watch for **custom-role creation**
  (`Microsoft.Authorization/roleDefinitions/write`) that hides `*` actions
  behind an innocuous name.
- **Credential adds to a service principal or app** -- done in *Entra*, not the
  Activity Log: a new secret or certificate on an app registration gives
  persistent, MFA-independent access. Correlate to the Entra audit log ("Add
  service principal credentials" / "Update application - Certificates and
  secrets management").
- **Managed-identity token abuse** -- a token minted for a compromised VM's
  system-assigned identity used to call ARM. The MI's object ID appears as
  `Caller` from an unexpected `CallerIpAddress`.
- **Code execution on VMs** --
  `Microsoft.Compute/virtualMachines/runCommand/action` and Custom Script
  Extension (`Microsoft.Compute/virtualMachines/extensions/write` installing
  `CustomScript`) run attacker code as SYSTEM/root without any RDP/SSH.
- **Compute/serverless persistence** -- `Microsoft.Web/sites` (App Service /
  Functions), Automation **Runbooks**, and Logic Apps as scheduled backdoors
  that re-mint credentials or re-grant roles.
- **Resource-level RBAC backdoors** -- a role assignment scoped to a single
  storage account or vault rather than the subscription, easy to miss in a
  top-level review.

```kusto
AzureActivity
| where TimeGenerated > ago(14d)
| where OperationNameValue has_any (
    "roleAssignments/write", "roleDefinitions/write",
    "runCommand/action", "virtualMachines/extensions/write")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceId
| order by TimeGenerated asc
```

The CLI equivalent filters the same operations:
`az monitor activity-log list --start-time <t> --query "[?contains(operationName.value,'roleAssignments/write')]"`.

## Identity-Plane Correlation

The Activity Log names the principal but not the human behind it. Map the
service principal or managed identity **object ID** back to Entra to see the
authentication context -- this is the cross-plane step, and it usually means
opening `investigating-m365-entra`.

```kusto
// Where did this service principal / managed identity actually sign in from?
AADServicePrincipalSignInLogs
| where ServicePrincipalId == "<sp-or-mi-object-id>"
| where TimeGenerated > ago(30d)
| project TimeGenerated, AppId, ServicePrincipalName, IPAddress,
    ResourceDisplayName, ResultType
| order by TimeGenerated asc

// For an interactive user: sign-ins around the abusive Activity Log calls
SigninLogs
| where UserPrincipalName == "attacker@contoso.com"
| project TimeGenerated, IPAddress, Location, AppDisplayName,
    ConditionalAccessStatus, AuthenticationRequirement, ResultType
```

Check conditional-access status and whether MFA was actually satisfied -- a
service principal bypasses interactive CA entirely, which is exactly why
attackers pivot to SP/MI credentials.

## Managed-Identity and SSRF Credential Theft

The Azure analogue of AWS IMDS theft: an SSRF or foothold on a VM / App Service
reads the Instance Metadata Service to lift the managed identity's token, then
uses it elsewhere.

```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

The signature is unmistakable: the managed identity's calls appear in
`AzureActivity` from a `CallerIpAddress` that is **not** the resource's own
outbound IP. The token is minted for that resource, so any call from an
unrelated or external IP means the token left the box.

```kusto
AzureActivity
| where TimeGenerated > ago(7d)
| where Caller == "<managed-identity-object-id>"
| summarize ops = count() by CallerIpAddress, OperationNameValue
| order by ops desc     // flag IPs that are not the VM's egress
```

Correlate the theft window with NSG flow logs (if enabled) for the outbound
SSRF and the reuse source. On App Service the token endpoint uses
`IDENTITY_ENDPOINT` with a header secret rather than 169.254.169.254 -- the same
off-resource-use logic applies.

## Defender for Cloud Alert Triage

Defender for Cloud is a starting pistol, not the investigation. Each alert maps
to a hypothesis you confirm in the Activity Log and diagnostic logs.

| Alert (representative) | Implication |
| --- | --- |
| Crypto-mining / `Digital currency mining` behavior | A VM is talking to a mining pool -- a principal with deploy rights was compromised. |
| Anomalous resource deployment / unusual `RunInstances`-equivalent | Attacker spinning up compute, often in an unused region. |
| Suspicious sign-in / access from a Tor or known-malicious IP | The stolen principal called from attacker infrastructure. |
| Managed identity / metadata credential exfiltration | The IMDS theft above -- confirm off-resource token use. |
| Access from anomalous location on a storage account / Key Vault | Data-plane access from an unexpected geography. |

```bash
az security alert list -o table
az security alert show --location <loc> -n <alert-name> -g <rg>
```

An alert older than the 90-day Activity Log window still carries the principal
and IPs -- pivot on those even after the raw events have aged out.

## Data-Theft Detection

- **Storage account key regeneration** --
  `Microsoft.Storage/storageAccounts/listKeys/action` and `regenerateKey`
  hand the attacker a full-access key that works outside RBAC and outside the
  Activity Log thereafter.
- **SAS-token minting** -- `listAccountSas` / `listServiceSas` produces a
  time-boxed exfil URL that leaves no per-object control-plane trail.
- **Blob exfil** -- visible only if data-plane diagnostic logging is on:
  `StorageBlobLogs` shows `GetBlob` volume by caller.
- **Public-access changes on containers** -- setting a container or account to
  allow anonymous/blob public access is exfil staging.
- **Disk snapshot export / sharing** --
  `Microsoft.Compute/snapshots/write` then `/beginGetAccess/action` mints a SAS
  download URL for a full disk image.
- **Key Vault secret dumps** -- `Microsoft.KeyVault/vaults/read` (`VaultGet`)
  to enumerate, then data-plane `SecretGet` reads (in `AzureDiagnostics` /
  `KeyVaultData`, only if logging was enabled).

```kusto
// Control-plane data-theft indicators
AzureActivity
| where TimeGenerated > ago(14d)
| where OperationNameValue has_any (
    "storageAccounts/listKeys", "storageAccounts/regenerateKey",
    "listAccountSas", "listServiceSas",
    "snapshots/write", "snapshots/beginGetAccess")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceId

// Key Vault data-plane reads -- only present if diagnostics were on beforehand
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet", "KeyGet", "VaultGet")
| project TimeGenerated, CallerIPAddress, identity_claim_upn_s, OperationName, id_s
```

## Anti-Forensics the Attacker Attempts

A capable attacker tries to blind you. The key operations to hunt -- and their
defeat:

- **Diagnostic-setting deletion** --
  `Microsoft.Insights/diagnosticSettings/delete` stops data-plane logs from
  reaching the workspace.
- **Activity Log export removal / narrowing** -- deleting the subscription-level
  diagnostic setting that ships the Activity Log to a workspace or storage.
- **Resource deletion** -- deleting the VM, snapshot, or storage account to
  destroy the artifact and its logs.

The defeat is the same shape as an AWS org trail: a **tenant-level export to a
central, locked destination** the compromised principal cannot reach --
immutable-storage (WORM/legal-hold) blob export, or Sentinel ingestion in a
segregated workspace with delete protection and resource locks. When export is
immutable, the attacker's own `diagnosticSettings/delete` call is logged there
before it takes effect, so cleanup becomes evidence rather than a gap. If you
lack it, record the blind window as a scoping limitation.

```kusto
AzureActivity
| where TimeGenerated > ago(14d)
| where OperationNameValue has_any (
    "diagnosticSettings/delete", "Microsoft.Insights/diagnosticSettings/write")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, ResourceId
```

## Evidence Preservation

- **Snapshot the involved VMs' disks** before touching them, and lock the
  snapshots so they cannot be deleted.

  ```bash
  az snapshot create -g <rg> -n IR-2026-042-osdisk \
    --source <os-disk-id> --tags case=IR-2026-042 legal-hold=true
  az lock create --name IR-2026-042-hold --lock-type CanNotDelete \
    --resource-group <rg> --resource-name IR-2026-042-osdisk \
    --resource-type Microsoft.Compute/snapshots
  ```

- **Export the relevant Activity Log window** before it ages out of 90-day
  retention -- run the CLI/KQL and save the JSON to a preserved, locked store.
- **Apply resource locks / legal hold** to evidence artifacts, and involve legal
  before collection if the incident may become a regulatory or litigation
  matter.

## Containment

Do it all at once, after scoping. Partial containment alerts the attacker.

- **Disable or rotate the compromised principal.** For a service principal /
  app, disable it and roll its credentials:

  ```bash
  az ad sp update --id <app-id> --set accountEnabled=false
  # remove attacker-added secrets/certs
  az ad app credential reset --id <app-id>
  ```

  For a user, disable the account and force a reset in Entra, then revoke
  sessions (below).

- **Revoke role assignments** the attacker granted:

  ```bash
  az role assignment delete --assignee <object-id> \
    --role Owner --scope /subscriptions/<sub-id>
  ```

- **Revoke sessions / refresh tokens** so existing tokens die (an Entra action
  -- `Revoke-MgUserSignInSession` / `az ad user ...`), because disabling alone
  leaves issued tokens valid up to an hour.
- **Isolate the VM** by swapping its NSG to a deny-all outbound rule rather than
  deleting it, so disk and memory survive for analysis (`az network nsg rule
  create ... --access Deny --direction Outbound --protocol '*'`).
- **Rotate storage keys and regenerate SAS** -- renewing both keys invalidates
  every outstanding SAS and access key at once:

  ```bash
  az storage account keys renew --account-name <acct> -g <rg> --key primary
  az storage account keys renew --account-name <acct> -g <rg> --key secondary
  ```

- **Remove attacker persistence** -- delete backdoor Functions/App Service,
  Automation runbooks, custom roles, and resource-scoped role assignments --
  only after they are documented.

Reach for **Azure CLI** and **KQL in Log Analytics / Sentinel** for the
investigation itself; **MicroBurst** and **ROADtools** for understanding the
TTPs an attacker would run (and what each leaves behind); and Microsoft's
Unified Audit correlation when the Azure story crosses into M365.

## Rationalizations to Reject

- *"The Activity Log shows nothing, so no data was touched."* The Activity Log
  is control plane only. Blob reads, secret fetches, and DB queries are
  data-plane operations that are invisible unless diagnostic logging was enabled
  *beforehand*. Absence there is not evidence of no exfil.
- *"Defender for Cloud didn't alert, so there's no compromise."* Defender covers
  a subset of behaviors and depends on the right plan and coverage. Absence of a
  finding is not evidence of absence -- the Activity Log timeline is
  authoritative.
- *"We disabled the user, so the account is contained."* Issued access tokens
  stay valid up to an hour, and any service-principal credentials or role
  assignments the attacker created survive the disable. Revoke sessions and
  audit every persistence mechanism.
- *"It's a managed identity, it can only be used from inside Azure."* That is the
  design, not a guarantee. SSRF/IMDS theft lifts the token off the resource; the
  off-resource `CallerIpAddress` is precisely the signature to hunt.
- *"The service principal only has Contributor, not Owner."* Contributor can run
  `runCommand` on VMs, read storage keys, and mint SAS tokens -- code execution
  and data theft without ever touching role assignments. Trace what the role can
  reach; do not assume.
- *"It's just crypto-mining, low priority."* Mining means a principal with
  deploy rights was compromised -- the same access could exfiltrate data or
  escalate through `roleAssignments/write`. Mining is the visible symptom, not
  the scope.
- *"Logs only go back 90 days, so the compromise started within 90 days."* That
  is the Activity Log's default retention, your visibility limit -- not the
  attacker's timeline. Record it as a scoping gap and check the workspace /
  immutable export for longer retention.

## References

- `investigating-m365-entra` -- the sibling identity-plane skill; open it to correlate the SP/MI back to Entra sign-ins and audit
- `investigating-aws-incidents` -- the sibling cloud-IR skill when the incident is in AWS
- `attacking-entra-id` -- the offensive side; how these tenant/subscription TTPs are executed
- `attacking-eks-gke-aks` -- when the pivot is specifically into AKS / Kubernetes
- `responding-to-incidents` -- the general IR process, evidence handling, and host-level response
- `reporting-security-findings` -- structuring the incident narrative and deliverable
- Azure CLI (`az`) -- drive the control plane and pull the Activity Log
- KQL in Log Analytics / Microsoft Sentinel -- query `AzureActivity`, `AzureDiagnostics`, and sign-in tables
- Microsoft Defender for Cloud -- alert source and finding-type reference
- MicroBurst and ROADtools -- emulate and understand Azure/Entra attack TTPs and what each leaves in the logs
