---
name: investigating-aws-incidents
description: Investigate security incidents in Amazon Web Services -- reconstruct attacker activity from CloudTrail, VPC Flow Logs, and GuardDuty, anchor the investigation on the compromised principal (access key or role), trace privilege escalation and persistence through IAM API calls, detect data exfiltration and crypto-mining, and contain without destroying evidence or tipping off the attacker. Use when responding to a suspected AWS compromise, exposed access keys, anomalous CloudTrail activity, a GuardDuty finding, unexpected IAM changes, crypto-mining EC2 instances, or S3 data exfiltration.
---

# Investigating AWS Incidents

In AWS an incident is reconstructed from logs the attacker usually could not
delete -- CloudTrail, VPC Flow Logs, and the control plane's own record of every
API call. The investigation is therefore a log-correlation exercise anchored on
the compromised principal: the access key or assumed role, and the sequence of
API calls it made. Find the principal, pull every event it generated, and the
rest of the intrusion falls out of the timeline.

## When to Use

- Exposed or leaked AWS access keys -- committed to a repo, in a pastebin, or flagged by AWS abuse
- Anomalous CloudTrail activity -- API calls from unfamiliar regions, IPs, or user agents
- A GuardDuty finding -- credential exfiltration, tor traffic, crypto-mining, or anomalous IAM behavior
- Unexpected IAM changes -- new users, keys, roles, login profiles, or policy attachments nobody authorized
- Crypto-mining EC2 -- a spike in on-demand instances, GPU families, or an unexpected billing alert
- S3 data exfiltration -- GetObject spikes, buckets made public, or shared snapshots

## When NOT to Use

- **The incident is in Microsoft 365 / Entra ID, not AWS** -- use `investigating-m365-entra`
- **The incident is in Azure resources/subscriptions** -- use `investigating-azure-incidents`
- **The general IR process and host-level response** -- use `responding-to-incidents`
- **You are the attacker, not the responder** -- use `exploiting-cloud-platforms`
- **The pivot is specifically into Kubernetes on EKS** -- use `attacking-eks-gke-aks`
- **Proactive hunting with no confirmed incident** -- use `hunting-threats`

## First-Hour Triage

Three actions, in order: identify the principal, pull its recent activity,
preserve before you contain.

**Scope the compromised principal.** Whether the report is a leaked key, a
GuardDuty finding, or a billing spike, resolve it to a single principal ARN --
an IAM user, a role, or the root account. That ARN is the anchor for everything
that follows.

```bash
# What is this key/session, and does it still work?
aws sts get-caller-identity                       # if you hold the suspect creds
# Resolve an access key ID to its owner
aws iam get-access-key-last-used --access-key-id AKIA...
# Enumerate the principal's current footprint
aws iam list-access-keys --user-name <user>
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
```

**Pull recent activity from the principal.** Event history (below) is the
fastest first look; the S3 log bucket is the source of truth.

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=<user> \
  --start-time 2026-07-01T00:00:00Z --max-results 200

# By access key -- catches role sessions that lookup-by-username misses
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIA...
```

**Isolate without tipping off -- snapshot then contain.** An attacker who sees
their key deactivated mid-operation will burn persistence you have not found
yet. For anything but active, ongoing damage: preserve evidence first (snapshot
volumes, export logs), map persistence, then contain everything at once. If
there is live damage -- active mining, active exfil -- stop the damage and
accept the trade.

## CloudTrail Deep-Dive

**Event history vs. the S3 log bucket.** The console Event history is searchable
but covers only 90 days of management events and drops data events. The
CloudTrail S3 log bucket (or CloudTrail Lake) is the authoritative record and
the only place with S3/Lambda data events -- query it, not the console, once you
are past the first look. Confirm what is actually logged:

```bash
aws cloudtrail describe-trails
aws cloudtrail get-trail-status --name <trail>          # IsLogging: true?
aws cloudtrail get-event-selectors --trail-name <trail> # data events on?
```

**`userIdentity` types** tell you what you are looking at:

| `type` | Meaning | Investigative note |
| --- | --- | --- |
| `IAMUser` | Long-lived user credentials | `accessKeyId` is the pivot. Human or service account? |
| `AssumedRole` | Temporary STS creds | Read `sessionContext.sessionIssuer` for the source role. |
| `AWSService` | An AWS service acting | Usually benign, but check for spoofed-looking service calls. |
| `Root` | Root account | Almost never legitimate for API calls. Treat as critical. |
| `FederatedUser` / `WebIdentityUser` | SAML/OIDC federation | Trace back to the IdP session. |

For `AssumedRole`, `sessionContext.sessionIssuer.arn` names the role and
`sessionContext.attributes.mfaAuthenticated` tells you whether MFA was used.

**Anomaly fields to grep:**

- `sourceIPAddress` -- external IPs on role credentials that should only run
  inside the VPC (the IMDS theft signature, below). Correlate against VPC Flow
  Logs.
- `userAgent` -- `aws-cli/2.x`, `Boto3`, `python-requests`, or anything with
  `kali` on a principal that normally shows console or SDK-from-Lambda agents.
- `awsRegion` -- calls in regions you do not operate in (attackers spin up
  mining in `ap-*` / `sa-*` to dodge attention). Enumeration touches many
  regions fast.
- `errorCode` -- a storm of `AccessDenied` / `UnauthorizedOperation` is
  enumeration: the attacker is mapping what the stolen principal can do.

```sql
-- Athena over the CloudTrail S3 bucket: AccessDenied enumeration storm
SELECT eventname, count(*) AS n
FROM cloudtrail_logs
WHERE useridentity.accesskeyid = 'AKIA...'
  AND errorcode = 'AccessDenied'
  AND eventtime > '2026-07-01T00:00:00Z'
GROUP BY eventname ORDER BY n DESC;
```

## Canonical Attacker API Patterns

Grep the timeline for this sequence. It is the shape of nearly every stolen-key
intrusion:

- **`GetCallerIdentity`** -- often the very first call. The attacker is
  confirming what the key is and who owns the account.
- **Enumeration** -- `List*` / `Get*` / `Describe*` across IAM, S3, EC2, RDS,
  Secrets Manager, often with an `AccessDenied` storm.
- **Privilege escalation** -- `CreateUser`, `CreateAccessKey`,
  `AttachUserPolicy` (watch for `AdministratorAccess`), `PutUserPolicy` (inline
  policy so it does not show in attached-policy lists), `CreateLoginProfile` (a
  console password on an API-only account), `UpdateLoginProfile`.
- **`iam:PassRole` abuse** -- passing a high-privilege role to a new EC2
  instance, Lambda, or Glue job to inherit its permissions. Look for `PassRole`
  paired with `RunInstances` / `CreateFunction`.
- **Trust-policy tampering** -- `UpdateAssumeRolePolicy` or `CreateRole` with a
  trust policy naming an external account (a cross-account backdoor).
- **STS chaining** -- `AssumeRole` into a more privileged role, then another,
  building a chain that launders the original stolen key.

```bash
# Pull the IAM mutating calls for the window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey
# Repeat for: CreateUser, AttachUserPolicy, PutUserPolicy, CreateLoginProfile,
#             UpdateAssumeRolePolicy, CreateRole, AssumeRole
# (iam:PassRole is a permission, not an event -- find it in requestParameters of
#  RunInstances / CreateFunction, not via lookup-by-EventName)
```

## Persistence Hunting

Enumerate every mechanism explicitly during eradication -- rotating the one
leaked key does nothing about a second one the attacker created.

- **New IAM users / keys / roles** created inside the incident window.
- **A second access key on an existing user** -- `CreateAccessKey` on the
  victim or another account; a user may have up to two keys.
- **Console login profiles on service accounts** -- `CreateLoginProfile` on a
  principal that never used the console is high-signal.
- **Modified role trust policies** -- `UpdateAssumeRolePolicy` adding an
  external principal or `sts:AssumeRole` from another account.
- **Lambda backdoors** -- a new or updated function that mints credentials or
  re-creates users, often on an EventBridge schedule.
- **EventBridge / CloudWatch Events rules** invoking attacker Lambda on a cron.
- **`iam:CreateServiceLinkedRole`** and other quietly-privileged roles.

```bash
# Users and keys created recently
aws iam list-users --query 'Users[?CreateDate>=`2026-07-01`].[UserName,CreateDate]'
for u in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam list-access-keys --user-name "$u" \
    --query 'AccessKeyMetadata[].[UserName,AccessKeyId,CreateDate]' --output text
done

# Roles whose trust policy names an external account
aws iam list-roles --query 'Roles[].[RoleName,AssumeRolePolicyDocument]'

# Recently modified Lambda and the EventBridge rules that fire them
aws lambda list-functions --query 'Functions[].[FunctionName,LastModified]'
aws events list-rules --query 'Rules[].[Name,ScheduleExpression,State]'
```

## IMDS / SSRF Credential Theft Signatures

The classic AWS escalation: an SSRF or foothold on an EC2 instance reads the
Instance Metadata Service (`http://169.254.169.254/latest/meta-data/iam/...`),
lifts the instance role's temporary credentials, and uses them elsewhere.

The signature is unmistakable in CloudTrail: **the instance role's session
credentials appear from a `sourceIPAddress` that is not the instance.** The role
is minted for the instance, so any call from an external or unrelated IP means
the credentials left the box.

```sql
-- Role session creds used from outside the VPC
SELECT eventtime, eventname, sourceipaddress, useragent
FROM cloudtrail_logs
WHERE useridentity.arn LIKE '%assumed-role/<instance-role>%'
  AND sourceipaddress NOT LIKE '10.%'
  AND sourceipaddress NOT LIKE '172.%'
ORDER BY eventtime;
```

IMDSv1 (a simple GET, no session token) makes this trivial and is itself a
finding -- confirm whether the instance enforces IMDSv2
(`HttpTokens: required`) via `aws ec2 describe-instances`. Correlate the theft
window with VPC Flow Logs for the outbound SSRF and the reuse source.

## GuardDuty Finding Triage

GuardDuty is a starting pistol, not the investigation. Each finding type maps to
a hypothesis you confirm in CloudTrail:

| Finding type | Implication |
| --- | --- |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*` | Instance role creds used off the instance -- the IMDS theft above. |
| `UnauthorizedAccess:IAMUser/MaliciousIPCaller` | A principal called from a known-bad IP. |
| `UnauthorizedAccess:IAMUser/TorIPCaller` | API calls via Tor -- almost never a legitimate admin. |
| `CryptoCurrency:EC2/BitcoinTool.B!DNS` | An instance talking to a mining pool -- confirmed crypto-mining. |
| `Recon:IAMUser/*` | Enumeration -- the `AccessDenied` storm. |
| `Persistence:IAMUser/*`, `PrivilegeEscalation:IAMUser/*` | IAM mutation matching the escalation patterns above. |
| `Policy:S3/BucketAnonymousAccessGranted` | A bucket was made public -- possible exfil staging. |

```bash
aws guardduty list-findings --detector-id <id> \
  --finding-criteria '{"Criterion":{"severity":{"Gte":4}}}'
aws guardduty get-findings --detector-id <id> --finding-ids <id>
```

Findings older than the CloudTrail window still carry the principal and IPs --
pivot on those even when the raw events have aged out of Event history.

## Data-Theft Detection

- **S3 GetObject spikes** -- a jump in `GetObject` volume/bytes on sensitive
  buckets, visible only if S3 data events are logged. Check request counts by
  principal.
- **Buckets made public** -- `PutBucketPolicy` / `PutBucketAcl` granting
  `AllUsers` or `AuthenticatedUsers`, or `PutPublicAccessBlock` disabling the
  block.
- **Snapshot sharing** -- `ModifySnapshotAttribute` or `ModifyImageAttribute`
  adding an external account or `all` to the volume/AMI (steal data by sharing
  the snapshot out).
- **RDS exfil** -- `ModifyDBSnapshotAttribute` sharing a DB snapshot, or
  `StartExportTask` dumping a snapshot to an attacker-controlled S3 bucket.

```sql
SELECT eventname, useridentity.arn, sourceipaddress,
       json_extract_scalar(requestparameters, '$.attributeType') AS attr
FROM cloudtrail_logs
WHERE eventname IN ('ModifySnapshotAttribute','ModifyImageAttribute',
                    'ModifyDBSnapshotAttribute','PutBucketPolicy','PutBucketAcl')
  AND eventtime > '2026-07-01T00:00:00Z';
```

## Anti-Forensics the Attacker Attempts

A capable attacker tries to blind you. Watch for and, crucially, work around:

- **`StopLogging` / `DeleteTrail`** -- turning off CloudTrail.
- **`PutEventSelectors`** -- narrowing what the trail records (dropping data
  events or a whole region) without deleting the trail.
- **`DeleteFlowLogs`** -- removing VPC Flow Logs to hide the network side.
- **`DeleteDetector` / `UpdateDetector` (disable) / suspend** -- killing
  GuardDuty.

The defeat for all of these is a **member-account-independent
Organizations-level trail** that logs to a central, locked S3 bucket (MFA
delete, Object Lock, separate log-archive account) the compromised principal
cannot reach. The very act of `StopLogging` is itself logged there before it
takes effect. If you have an org trail, the attacker's cleanup calls are
evidence, not gaps. If you do not, note the blind window as a scoping
limitation.

```bash
# Was logging tampered with? These calls are the finding.
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging
# Repeat: DeleteTrail, PutEventSelectors, DeleteFlowLogs, DeleteDetector
```

## Evidence Preservation

- **EBS snapshots** of every involved instance's volumes, before you touch the
  instance. Tag with the case ID and apply a resource policy / legal hold so
  they cannot be deleted.

  ```bash
  aws ec2 create-snapshot --volume-id vol-xxx \
    --description "IR-2026-042 preserve" \
    --tag-specifications 'ResourceType=snapshot,Tags=[{Key=case,Value=IR-2026-042},{Key=legal-hold,Value=true}]'
  ```

- **Memory capture on a live instance** before termination -- for a resident
  implant or in-memory creds, this is the only source. Acquire and then analyze
  per `analyzing-memory-images`.
- **Export the relevant CloudTrail window** to a preserved location, and copy
  VPC Flow Logs and any GuardDuty findings before retention expires.
- **Tagging and legal hold** on all evidence artifacts, and involve legal before
  collection if the incident may become a regulatory or litigation matter.

## Containment and Eradication

Do it all at once, after scoping. Partial containment alerts the attacker.

- **Deactivate, do not delete, keys** -- deletion destroys the artifact; a
  deactivated key still shows in the timeline.

  ```bash
  aws iam update-access-key --user-name <user> \
    --access-key-id AKIA... --status Inactive
  ```

- **Revoke active sessions** -- deactivating a key does not kill in-flight
  temporary sessions minted from it. Attach an inline deny policy that invalidates
  any session/token issued before now (the `AWSRevokeOlderSessions` pattern):

  ```bash
  aws iam put-user-policy --user-name <user> \
    --policy-name AWSRevokeOlderSessions \
    --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny",
      "Action":"*","Resource":"*","Condition":{"DateLessThan":
      {"aws:TokenIssueTime":"2026-07-20T00:00:00Z"}}}]}'
  ```

  For a role, put an equivalent deny in the role's inline policy or a boundary.

- **Rotate** every credential the principal could reach: other keys, secrets in
  Secrets Manager / SSM the principal read, and any hardcoded creds on
  compromised instances.
- **Quarantine security group** -- move a mining or exfil instance to an SG with
  no egress rather than terminating it, so memory and disk survive for analysis.
- **Remove attacker persistence** -- delete the created users/keys/roles, revert
  tampered trust policies, remove backdoor Lambda and EventBridge rules -- only
  after they are documented.

## Rationalizations to Reject

- *"GuardDuty didn't alert, so nothing happened."* GuardDuty covers a subset of
  behaviors and depends on being enabled in the right regions. Absence of a
  finding is not evidence of absence -- the CloudTrail timeline is authoritative.
- *"We rotated the leaked key, so we're done."* The leaked key was step one. A
  second key, a new user, a modified trust policy, or a backdoor Lambda survives
  rotation. Enumerate every persistence mechanism before you close.
- *"The activity came from an AWS IP range, so it's legitimate."* Attackers run
  their tooling on EC2 too. Correlate the principal, user agent, and behavior --
  not just the IP owner.
- *"CloudTrail shows no CreateUser, so there's no persistence."* Inline policies
  (`PutUserPolicy`), a second access key on an existing user, and modified role
  trust policies all grant persistence without ever creating a user.
- *"It's just crypto-mining, low priority."* Mining means a principal with
  `RunInstances` was compromised -- the same access could exfiltrate data or
  escalate. Mining is the visible symptom, not the scope.
- *"The instance role is low-privilege, so the SSRF doesn't matter."* Confirm it.
  `iam:PassRole` and `AssumeRole` chains routinely turn a modest instance role
  into account-wide access. Trace what the role can reach, don't assume.
- *"Logs only go back 90 days, so the compromise started within 90 days."* That
  is your visibility limit, not the attacker's timeline. Record it as a scoping
  gap and check the org trail / Lake for longer retention.

## References

- `investigating-m365-entra` -- the sibling cloud-IR skill for M365 / Entra ID incidents
- `responding-to-incidents` -- the general IR process, evidence handling, and host-level response
- `exploiting-cloud-platforms` -- the offensive side; how these AWS TTPs are executed
- `attacking-eks-gke-aks` -- when the pivot is specifically into Kubernetes on EKS
- `analyzing-memory-images` -- working an instance memory capture with Volatility
- `hunting-threats` -- proactive hunting when there is no confirmed incident
- `reporting-security-findings` -- structuring the incident narrative and deliverable
- AWS CLI, Athena, and CloudTrail Lake -- query the authoritative logs
- `cloudtrail-partitioner` -- partition the CloudTrail S3 bucket for fast Athena queries
- Prowler -- retrospective posture and misconfiguration assessment of the account
- `stratus-red-team` -- emulate AWS attack TTPs to learn what each leaves in CloudTrail
- AWS Security Incident Response Guide; GuardDuty finding-type reference
