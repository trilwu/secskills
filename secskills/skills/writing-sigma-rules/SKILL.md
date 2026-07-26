---
name: writing-sigma-rules
description: Author and maintain Sigma detection rules — structure, logsource taxonomy, detection logic with modifiers, false-positive filtering, backend conversion with pySigma, and offline validation with Hayabusa or Chainsaw. Use when translating threat intel into vendor-agnostic detection logic, building a detection-as-code pipeline around Sigma, reviewing or tuning existing Sigma rules, or converting rules across SIEM backends.
---

# Writing Sigma Rules

Sigma is the common language for detection logic -- write once, convert to any
SIEM. The value is portability and reviewability, but only if the rule is
precise: a Sigma rule that matches everything is worse than no rule, because it
consumes analyst time and trains the team to ignore alerts. The work is
specificity without brittleness.

## When to Use

- Translating a TTP, threat intel report, or incident finding into a portable detection rule
- Writing vendor-agnostic detection logic that converts to multiple SIEM backends
- Building or maintaining a detection-as-code pipeline centered on Sigma
- Reviewing or tuning existing Sigma rules for precision and false-positive reduction
- Converting Sigma rules between backends (Splunk, Elastic, Sentinel, CrowdStrike, Chronicle)
- Contributing rules upstream to SigmaHQ or maintaining a private rule repository

## When NOT to Use

- **Broader detection engineering including YARA, Suricata, and the full detection lifecycle** -- use `engineering-detections`
- **The signature belongs on files or memory, not log telemetry** -- use `writing-yara-rules`
- **Hypothesis-driven threat hunting, not rule writing** -- use `hunting-threats`
- **Active incident response, not rule development** -- use `responding-to-incidents`

## Sigma Rule Structure

Every rule is a YAML document with these fields in order:

```yaml
title: Short Descriptive Name              # required, max ~100 chars
id: a1b2c3d4-0000-4000-8000-000000000001  # required, UUIDv4, never reuse
related:                                    # optional, link to predecessor rules
  - id: <uuid>
    type: derived | obsoletes | merged | renamed | similar
status: experimental | test | stable       # required, lifecycle stage
description: >                             # required, what and why
  Detects X behaviour consistent with Y technique.
references:                                # recommended
  - https://attack.mitre.org/techniques/T1059/001/
author: Your Name                          # required
date: 2026/07/26                           # required, YYYY/MM/DD
modified: 2026/07/26                       # required when updating
tags:                                      # required, ATT&CK mappings
  - attack.execution                       #   tactic (lowercase, dotted)
  - attack.t1059.001                       #   technique (lowercase)
logsource:                                 # required
  category: process_creation
  product: windows
detection:                                 # required
  selection:
    CommandLine|contains: 'some-indicator'
  condition: selection
falsepositives:                            # required
  - Legitimate admin scripts using the same flag
level: medium                              # informational|low|medium|high|critical
```

**Status lifecycle.** `experimental` = observation only, no alerting. `test` =
validated against emulation, ready for limited deployment. `stable` = tuned in
production with documented FPs. Never promote without the corresponding work.

## Logsource Taxonomy

The `logsource` block abstracts the data source. Specify only what is needed.

**Categories:** `process_creation`, `file_event`, `file_access`,
`network_connection`, `registry_event`, `dns_query`, `image_load`,
`pipe_created`, `process_access`, `driver_load`, `create_remote_thread`.

**Product:** `windows`, `linux`, `macos`.

**Service:** `sysmon`, `security`, `system`, `powershell`, `powershell-classic`,
`application`, `taskscheduler`, `windefend`, `firewall-as`.

Use `category` when you care about the event type regardless of collection
method. Use `product` + `service` when targeting a specific log channel.
Do not combine `category` and `service` unless the backend requires it.

## Detection Logic

### Selection and filter pattern

Define what to match (`selection`), what to exclude (`filter_*`), combine in
`condition`:

```yaml
detection:
  selection:
    ParentImage|endswith: '\explorer.exe'
    CommandLine|contains|all:
      - 'powershell'
      - '-enc'
  filter_legitimate:
    CommandLine|contains: 'company-deploy-script'
    User|startswith: 'SVC_'
  condition: selection and not filter_legitimate
```

### Condition syntax

```
condition: selection                           # simple match
condition: selection and not filter            # match minus exclusions
condition: selection1 or selection2            # either pattern
condition: (sel1 and sel2) and not (fp1 or fp2)
condition: all of selection*                   # all blocks starting with "selection"
condition: 1 of selection*                     # any one block
```

### Keywords

Match against the full log event (all fields). Blunt instrument -- prefer
field-specific selections for production rules:

```yaml
detection:
  keywords:
    - 'Invoke-Mimikatz'
    - 'sekurlsa::logonpasswords'
  condition: keywords
```

### Modifiers

Chain with `|`. Example: `CommandLine|contains|all`.

| Modifier | Effect |
| --- | --- |
| `contains` | Substring match |
| `startswith` / `endswith` | Prefix / suffix match |
| `re` | Regular expression (PCRE) |
| `base64offset` | Match base64-encoded variants at all three offsets |
| `all` | All list values must match (default is any) |
| `cidr` | CIDR network range match on IP fields |
| `windash` | Match both `-` and `/` as argument prefix |
| `expand` | Expand environment variables like `%SystemRoot%` |
| `wide` / `utf8` | Match UTF-16LE / UTF-8 encoding |
| `exists` | Field present (true) or absent (false) |

## Common Detection Patterns

### Process creation -- suspicious command line

```yaml
detection:
  selection:
    CommandLine|contains|windash|all: ['bypass', 'hidden', 'noprofile']
  filter_admin:
    ParentImage|endswith: ['\sccm.exe', '\intune_agent.exe']
  condition: selection and not filter_admin
```

### Parent-child relationship (Office spawning shell)

```yaml
detection:
  selection:
    ParentImage|endswith: '\winword.exe'
    Image|endswith: ['\cmd.exe', '\powershell.exe', '\wscript.exe', '\mshta.exe']
  condition: selection
```

### File creation in suspicious paths

```yaml
detection:
  selection:
    TargetFilename|contains: ['\AppData\Local\Temp\', '\ProgramData\', '\Users\Public\']
    TargetFilename|endswith: ['.exe', '.dll', '.scr', '.hta']
  condition: selection
```

### Registry persistence (run keys)

```yaml
detection:
  selection:
    TargetObject|contains: ['\CurrentVersion\Run\', '\CurrentVersion\RunOnce\']
    EventType: SetValue
  filter_installers:
    Image|startswith: 'C:\Windows\Installer\'
  condition: selection and not filter_installers
```

### Named pipe creation (C2 indicators)

```yaml
detection:
  selection:
    PipeName: ['\MSSE-*', '\postex_*', '\msagent_*', '\status_*']
  condition: selection
```

### WMI event subscription and scheduled task creation

WMI: logsource `product: windows`, `service: sysmon`, match `EventID: 21`,
`Operation: Created`. Scheduled tasks: logsource `category: process_creation`,
match `Image|endswith: '\schtasks.exe'` with `CommandLine|contains|all:
['/create', '/sc']`, filter on SYSTEM + known management tools.

## False Positive Handling

### The filter pattern

Exclusions go in named `filter_*` blocks, never inline with the selection.
Use `condition: selection and not 1 of filter_*` to apply all filters.

### Known-good exclusions

Filter on properties the attacker cannot control: full file paths of signed
vendor binaries (not filenames alone), service account SIDs (not usernames),
parent-child pairs from specific software workflows, verified certificate
subjects. Never filter on filenames alone, attacker-controllable command-line
fragments, or hostnames without justification.

### Severity calibration

| Level | Response expectation |
| --- | --- |
| `informational` | Automated tagging, correlation input only |
| `low` | Batch review, daily triage |
| `medium` | Analyst queue, investigate within hours |
| `high` | Prompt investigation, likely malicious |
| `critical` | Immediate response, active compromise |

Set level based on expected TP rate and business impact, not on how dangerous
the technique sounds. A noisy `critical` rule causes more damage than a
precise `medium` one.

### Correlation rules

When a single event is too common to alert on, use Sigma correlation rules
that reference other rules by ID, group by a field (e.g., `ComputerName`),
and require a threshold within a time window:

```yaml
title: Correlation - Multiple Suspicious Events from Same Host
type: correlation
rules:
  - id: <uuid-of-rule-1>
  - id: <uuid-of-rule-2>
group-by: [ComputerName]
timespan: 15m
condition:
  gte: 2
level: high
```

## Backend Conversion

### sigma-cli with pySigma

```bash
pip install sigma-cli pySigma-backend-splunk pySigma-backend-elasticsearch \
  pySigma-backend-kusto pySigma-backend-qradar

sigma convert -t splunk -p sysmon rules/rule.yml
sigma convert -t elasticsearch -p ecs_windows rules/rule.yml
sigma convert -t kusto -p microsoft_xdr rules/rule.yml
sigma convert -t qradar rules/rule.yml
sigma convert -t splunk -p sysmon rules/                     # entire directory
sigma convert -t splunk -p sysmon -f savedsearches rules/    # output format
```

### Pipeline selection

| Backend | Common pipelines |
| --- | --- |
| Splunk | `sysmon`, `splunk_windows`, `splunk_cim` |
| Elastic | `ecs_windows`, `ecs_zeek`, `filebeat` |
| Sentinel/XDR | `microsoft_xdr`, `azure_monitor` |
| CrowdStrike | `crowdstrike` |
| Chronicle | `chronicle_default` |

Always verify converted output against your actual field names. Pipeline
defaults may not match custom parsing configurations.

## Testing and Validation

### Schema validation

```bash
sigma check rules/rule.yml       # single rule
sigma check rules/               # entire directory
```

Common failures: missing or duplicate `id`, invalid `level`, malformed YAML,
undefined modifier, empty detection block.

### Offline validation against EVTX

```bash
hayabusa csv-timeline -d ./sample_evtx/ -r rules/rule.yml
chainsaw hunt ./sample_evtx/ -s rules/rule.yml --mapping mappings/sigma-mapping.yml
```

### Testing workflow

1. **Collect sample logs.** Run the technique in a lab (Atomic Red Team,
   Caldera) and capture EVTX or JSON.
2. **Verify detection.** Run Hayabusa/Chainsaw -- rule must fire on the TP log.
3. **Verify exclusion.** Run against clean baseline. Every hit characterized.
4. **Convert and test.** Run the backend query against 7+ days of production
   data. Characterize every match.
5. **Document.** Record TP/FP counts, FP causes, filters added. Update the
   rule's `falsepositives` field and the PR description.

## Quality Standards

**SigmaHQ requirements:** valid UUIDv4 `id`; `status` set appropriately
(`experimental` for new); `date`/`modified` in `YYYY/MM/DD`; at least one
ATT&CK tag; non-empty `falsepositives` (even `Unknown`); `level` based on TP
rate; descriptive `description`; `references` linking to source intel.

**YAML formatting:** two-space indent, no tabs; pipe-separated modifiers
without spaces (`field|contains|all`); dash-space lists; single-quoted strings
with special characters; folded scalar (`>`) for long descriptions; one rule
per file, snake_case filename matching the title.

**Field naming:** use Sigma standard names (`Image`, `ParentImage`,
`CommandLine`, `User`, `TargetFilename`, `TargetObject`, `DestinationIp`,
`DestinationPort`, `SourceIp`, `PipeName`, `Hashes`). Backend conversion
handles translation. Writing backend-specific field names defeats portability.

**Tag compliance:** `attack.<tactic>` (lowercase, hyphenated) and
`attack.t<number>` (lowercase, dotted sub-technique). Add `cve.YYYY.NNNNN`
when applicable. Verify IDs against the current ATT&CK release -- stale IDs
from retired techniques create mapping errors downstream.

## Rationalizations to Reject

- *"The rule is simple enough, it does not need testing."* Simple rules have
  the widest match surface. The simpler the logic, the more important the
  FP analysis.
- *"We will add filters after it goes live."* Every hour a noisy rule runs
  in production erodes analyst trust. Test and filter before deployment.
- *"Just use keywords, field-specific matching is too narrow."* Keywords match
  across all fields. A hit on a hostname that contains the string is noise.
- *"The converted output looks right, no need to test it."* Conversion assumes
  your field mappings match pipeline defaults. Verify against actual data.
- *"One rule per technique is enough."* Techniques have many procedures. T1059
  covers PowerShell, cmd, bash, Python, VBScript -- each needs its own logic.
- *"The rule works in Splunk, so it works everywhere."* Portability requires
  correct logsource abstraction. Backend-specific field names break it.
- *"Set it to critical -- credential dumping is always critical."* Severity
  reflects signal quality, not technique category. A noisy critical rule
  causes more damage than a precise medium one.

## References

- `engineering-detections` -- the full detection lifecycle including YARA, Suricata, and coverage measurement
- `hunting-threats` -- hypothesis-driven hunting that produces the findings rules are built from
- `mapping-attack-techniques` -- ATT&CK technique resolution and the purple-team loop
- `reporting-security-findings` -- writing up what the detection found
