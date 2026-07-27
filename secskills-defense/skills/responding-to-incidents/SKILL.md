---
name: responding-to-incidents
description: Run digital forensics and incident response — triage, evidence acquisition with chain of custody, host and cloud artifact analysis, timeline reconstruction, scoping, containment, eradication, and postmortem. Use during a suspected compromise, when analyzing a disk or memory image, reconstructing an attacker timeline, or answering how far an intrusion spread.
---

# Responding to Incidents

Two questions drive every incident: **how far did they get**, and **are they
still here**. Everything else — the malware, the CVE, the root cause — is
supporting detail. Answer those two in order and the response follows.

## When to Use

- Suspected or confirmed compromise of a host, account, or cloud tenant
- Forensic analysis of a disk image, memory capture, or log set
- Reconstructing what an attacker did and when
- Scoping blast radius and deciding containment
- Writing a postmortem or a regulator/customer-facing incident narrative

## When NOT to Use

- **Deep analysis of a recovered sample** — use `analyzing-malware`
- **Proactive searching with no known incident** — use `hunting-threats`
- **Deciding whether an alert is even an incident yet** — use
  `triaging-security-alerts`; response begins once triage confirms a true
  positive
- **Building the detections that would have caught it** — use `engineering-detections`
- **The incident is in AWS** (exposed keys, CloudTrail/GuardDuty) — use
  `investigating-aws-incidents`; in Microsoft 365 / Entra — use `investigating-m365-entra`
- **You have a packet capture to work through** — use `analyzing-network-traffic`
- **Service outages with no security dimension** — this is a security IR skill

## Route to a Depth Skill

Specific evidence types have their own procedure skill. This skill sets scope
and order; reach for these when a single artifact type becomes the focus.

| Artifact / focus | Skill |
| --- | --- |
| A RAM capture to work through with Volatility (injected code, in-memory creds, dead-process connections) | `analyzing-memory-images` |
| A Microsoft 365 / Entra ID compromise: no disk or memory, only cloud logs (UAL, sign-ins, OAuth grants) | `investigating-m365-entra` |
| Finding how an attacker persisted on a Linux host — the systematic sweep across every init path | `analyzing-linux-persistence` |

## The Order That Matters

```
Preparation → Detection & Analysis → Containment → Eradication → Recovery → Lessons Learned
                      ↑__________________|
                    (re-scope after every new finding)
```

Two rules that are violated constantly and cost the most:

**Preserve before you remediate.** Rebooting, reimaging, or "just cleaning it
up" destroys memory, running process state, and unflushed logs. Once gone, you
cannot answer the scoping question, and you will be guessing about whether you
got them out.

**Do not contain half of it.** Partial containment tells the attacker you have
noticed and gives them time to re-establish access from the parts you missed.
Scope first, then contain everything at once — unless there is active,
ongoing damage, in which case stop the damage and accept the trade.

## Evidence Acquisition

**Order of volatility** (RFC 3227 §2.1) — collect top to bottom:

```
registers, cache
routing table, arp cache, process table, kernel statistics, memory
temporary file systems            ← tmpfs, /dev/shm: staging lives here
disk
remote logging and monitoring data relevant to the system
physical configuration, network topology
archival media
```

Note that the RFC places memory, the process table, and network state in the
**same** tier rather than ordering them against each other. Modern practice
refines that: capture memory *first*, because the commands you would run to
enumerate processes and sockets execute on the box and perturb the memory you
have not captured yet. Do not skip the temporary filesystems tier — `/dev/shm`
and tmpfs are ordinary staging locations and they do not survive the reboot
that someone will inevitably suggest.

```bash
# Memory first, always, on a live suspect host
# Linux
sudo ./avml mem.lime                 # or LiME
# Windows
DumpIt.exe /OUTPUT mem.raw           # or winpmem
# macOS — do NOT reach for osxpmem. Rekall is archived, its last release was
# 2017 and Intel-only, and its kext-based approach is blocked by SIP and
# kext restrictions on Big Sur and later, and on all Apple Silicon. Full-RAM
# capture on a modern Mac realistically needs commercial tooling with the
# required Apple entitlements (e.g. Volexity Surge Collect). If none is
# available, do not stall the response: take process-scoped dumps and a
# comprehensive live-triage collection instead, and record in the incident
# log that full physical memory was not obtainable and why.

# Volatile state before you touch the disk
ps auxwwf; ss -tunap; lsof -n; last -Faiw; w
netstat -anob                        # Windows
Get-NetTCPConnection | Where State -eq Established

# Disk: image, do not analyze in place
sudo dd if=/dev/sda bs=4M conv=noerror,sync status=progress | tee image.dd | sha256sum
sudo ewfacquire /dev/sda             # E01 with built-in hashing, preferred
# Mount read-only, always via a write blocker or loop with `ro`
sudo mount -o ro,noexec,noload,loop image.dd /mnt/evidence
```

**Chain of custody is not paperwork you add later.** Record at collection time:

```
Evidence ID | Source host/serial | Collected by | UTC timestamp | Method/tool+version
SHA-256 at acquisition | SHA-256 at each transfer | Custodian at each handoff | Storage location
```

Hash immediately, verify after every copy, and never work on the original.
If the incident may become litigation or a regulatory matter, involve legal
before collection, not after.

## Triage Collection

For most incidents, a full disk image per host is too slow. Use targeted
collection at scale, then image only the hosts that matter.

```bash
# Windows: KAPE with the SANS triage target set
kape.exe --tsource C: --target !SANS_Triage --tdest E:\out --vhdx host01

# Linux/macOS: UAC or a scripted collection
./uac -p full /evidence/host01

# Cloud/EDR: pull the equivalent via API
# - EDR raw telemetry for the window ±7 days
# - Snapshot the volume before terminating any instance
aws ec2 create-snapshot --volume-id vol-xxx --description "IR-<case> preserve"
```

## Artifact Analysis by Question

Go to the artifact that answers your question rather than processing
everything.

| Question | Windows | Linux | macOS |
| --- | --- | --- | --- |
| What executed? | Prefetch, Amcache, ShimCache, SRUM, Sysmon E1 | `auditd`, shell history, `/var/log/*`, systemd journal | ExecPolicy DB, `/var/db/`, unified log |
| Persistence? | Run keys, Services, Scheduled Tasks, WMI subs, startup folder | cron, systemd units, `.bashrc`, `ld.so.preload`, init | LaunchAgents/Daemons, login items, profiles |
| Lateral movement? | 4624 type 3/10, 4648, 4672, RDP logs, SMB shares | `auth.log`, `wtmp`, `.ssh/authorized_keys`, known_hosts | Same as Linux plus ARD logs |
| Credential access? | LSASS handles (Sysmon E10), 4688 with `procdump` | `/etc/shadow` reads, `ptrace`, memory of `sshd` | Keychain access logs |
| Data staged/exfiltrated? | Recycle bin, `$MFT` timestamps, archive creation, USN journal | `find -newermt`, large tmp files, `tar`/`zip` in history | Same |
| Files accessed? | `$MFT`, `$UsnJrnl`, LNK, JumpLists, shellbags | atime (if enabled), `auditd` | FSEvents |
| Browser/download? | History DBs, `Zone.Identifier` ADS | Browser profile DBs | Quarantine DB (`LSQuarantine`) |

```bash
# Memory analysis — where "are they still here" usually gets answered
volatility3 -f mem.raw windows.pstree
volatility3 -f mem.raw windows.malfind          # injected RWX regions
volatility3 -f mem.raw windows.netscan
volatility3 -f mem.raw windows.cmdline
volatility3 -f mem.raw linux.bash               # recovered shell history

# Filesystem timeline
fls -r -m / image.dd > body.txt && mactime -b body.txt -d > timeline.csv
log2timeline.py --storage-file plaso.db image.dd && psort.py -o dynamic plaso.db > super.csv
```

## Cloud and Identity Incidents

Most modern intrusions run through identity, not malware. Do not stop at the
host.

```bash
# AWS
aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=<user>
# Look for: CreateAccessKey, AttachUserPolicy, AssumeRole chains, ConsoleLogin
# without MFA, GetSecretValue, CreateTrail/StopLogging (anti-forensics)

# Azure / Entra ID
# SigninLogs: impossible travel, legacy auth, unfamiliar device
# AuditLogs: "Add service principal credentials", "Consent to application",
#            "Update conditional access policy", role assignments

# Google Workspace / GCP
# Admin audit: OAuth token grants, mail forwarding rules, delegation changes
```

Attacker-created OAuth applications, service principal credentials, and mail
forwarding rules are the most-missed persistence in cloud incidents. Enumerate
them explicitly during eradication.

## Timeline Reconstruction

The timeline is the deliverable that everything else supports.

- **UTC everywhere.** Normalize on ingest and record the source timezone.
- **Cite the source artifact for every row.** An uncited timeline cannot be
  defended or re-derived.
- **Separate observed from inferred.** "Process created (Sysmon E1)" is
  observed; "attacker pivoted here" is inference. Mark them differently.
- **Beware timestomping.** `$MFT` `$STANDARD_INFORMATION` is trivially forged;
  `$FILE_NAME` is not. Disagreement between them is itself a finding.
- **Establish the earliest evidence of compromise, then look earlier.** The
  first thing you find is almost never the first thing that happened.

```
UTC Timestamp        | Host    | Event                                  | Source            | O/I
2026-07-12 03:14:02  | WEB01   | POST /upload.aspx 200, 1.2MB, IP x.x.x.x| IIS log           | O
2026-07-12 03:14:40  | WEB01   | w3wp.exe → cmd.exe → whoami            | Sysmon E1         | O
2026-07-12 03:15:05  | WEB01   | Initial access via upload vuln          | correlation       | I
```

## Scoping

Do not contain until you have answered these, or you will contain the wrong
subset:

1. **Patient zero** — first host/account, and initial access vector
2. **Every credential the attacker could have obtained** — anything cached,
   typed, stored, or reachable from a compromised host is burned
3. **Every host those credentials touched** — pivot through auth logs, not
   just EDR alerts
4. **Persistence inventory** — per host and per identity, listed explicitly
5. **Data exposure** — what was accessible, what was accessed, what left

Scoping expands. When a new host appears, restart step 2 for it.

## Containment and Eradication

```bash
# Contain without destroying evidence
# - Network-isolate via EDR rather than powering off (preserves memory)
# - Revoke sessions and tokens, not just passwords: OAuth grants, refresh
#   tokens, Kerberos TGTs, API keys, SSH keys
# - Disable rather than delete accounts, so the artifacts survive

# Eradication checklist, per compromised identity
#   password reset, MFA re-enrollment, session/token revocation, key rotation
# For AD-wide compromise: krbtgt reset twice, ~10h apart
```

Reimage rather than clean when the attacker had SYSTEM/root. You cannot prove
removal of an implant on a host you do not fully understand, and the cost of
being wrong is the whole investigation repeating.

**Recovery gates** — do not restore until: initial access vector is closed,
all identified persistence is removed, credentials are rotated, and detection
exists for the observed TTPs. Monitor restored systems at elevated sensitivity
for at least a full business cycle.

## Rationalizations to Reject

- *"Let's reimage it now and investigate later."* Reimaging is the end of the
  investigation for that host.
- *"Only one host alerted, so only one host is affected."* Alerts show
  detection coverage, not attacker footprint.
- *"We reset the password, the account is safe."* Refresh tokens, app
  passwords, and existing sessions survive a password reset.
- *"The EDR would have caught it."* It did not catch the part you are looking
  at now. Assume gaps and corroborate with independent artifact sources.
- *"AV cleaned it."* AV removes a file. It does not remove persistence,
  credentials, or a second implant.
- *"The logs only go back 7 days, so we can't know."* Say that as a scoping
  limitation in the report. Do not let it become an implicit "nothing happened
  before day 7."
- *"Let's not write it down until we're sure."* Contemporaneous notes are the
  evidence. Record uncertainty explicitly instead of delaying.

## Deliverable

- **Executive summary** — what happened, impact, current status, in plain language
- **Timeline** — UTC, sourced, observed vs inferred
- **Scope** — hosts, accounts, and data, with the basis for each inclusion and
  exclusion
- **Root cause** — the initial access vector and the control that failed
- **Actions taken** — containment, eradication, recovery, with timestamps
- **Evidence register** — items, hashes, custody
- **Gaps** — what could not be determined and why (log retention, no EDR, etc.)
- **Recommendations** — prioritized, each tied to a specific failure in the narrative

Postmortems are blameless: they analyze the control and process failures, not
the person who clicked. A postmortem that names an individual as the cause
produces silence in the next incident.

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Persistence** (TA0003)

- [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Additional Cloud Credentials — see also `exploiting-cloud-platforms`
- [T1098.002](https://attack.mitre.org/techniques/T1098/002/) Additional Email Delegate Permissions

**Defense Evasion** (TA0005)

- [T1070](https://attack.mitre.org/techniques/T1070/) Indicator Removal
- [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Clear Windows Event Logs — see also `hunting-threats`
- [T1070.006](https://attack.mitre.org/techniques/T1070/006/) Timestomp
- [T1562](https://attack.mitre.org/techniques/T1562/) Impair Defenses — see also `hunting-threats`
- [T1562.001](https://attack.mitre.org/techniques/T1562/001/) Disable or Modify Tools — see also `hunting-threats`

**Collection** (TA0009)

- [T1114](https://attack.mitre.org/techniques/T1114/) Email Collection

**Impact** (TA0040)

- [T1485](https://attack.mitre.org/techniques/T1485/) Data Destruction
- [T1486](https://attack.mitre.org/techniques/T1486/) Data Encrypted for Impact — see also `analyzing-malware`
- [T1489](https://attack.mitre.org/techniques/T1489/) Service Stop
- [T1490](https://attack.mitre.org/techniques/T1490/) Inhibit System Recovery — see also `hunting-threats`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `analyzing-malware` — sample analysis feeding scoping and IOCs
- `hunting-threats` — proactive search using the TTPs found here
- `engineering-detections` — closing the detection gap this incident exposed
- NIST SP 800-61r3 (incident handling), SP 800-86 (forensic techniques), RFC 3227
- Volatility 3, Plaso/log2timeline, KAPE, Velociraptor, TheHive as core tooling
