---
name: hunting-threats
description: Run hypothesis-driven threat hunts across endpoint, network, cloud, and identity telemetry using stack counting, outlier analysis, and ATT&CK-based hypotheses, with SIEM query patterns for Splunk, KQL, and Elastic. Use when proactively searching for undetected compromise, validating an intel report against your environment, or converting a hunch into a repeatable hunt.
---

# Hunting Threats

Hunting starts from an assumption of failure: the controls are deployed, no
alert has fired, and the adversary may still be present. The output is not
usually a compromise — it is a detection, a telemetry gap, or a documented
negative result. Hunts that only count as successful when they find something
degrade into confirmation bias.

## When to Use

- Proactively searching for compromise that detection missed
- Testing a specific hypothesis about attacker behaviour in your environment
- Operationalizing a threat intel report against your telemetry
- Validating that a control or detection actually works in production
- Baselining an environment to enable future outlier analysis

## When NOT to Use

- **Confirmed incident in progress** — use `responding-to-incidents`
- **Writing the rule for what you found** — use `engineering-detections`
- **Sample analysis** — use `analyzing-malware`
- **Offensive testing of defenses** — use the red team skills

## Hypothesis Before Query

An unstructured search through logs is browsing, not hunting. Every hunt gets
a written hypothesis in this shape:

> **Hypothesis:** An adversary with [access level] is using [technique] to
> [objective], which would produce [observable] in [data source], which is
> distinguishable from normal because [discriminator].
>
> **If true, I expect to see:** ...
> **If false, I expect:** ...
> **Telemetry required:** ... (verified present: yes/no)

If you cannot name the discriminator — what makes the malicious instance look
different from the thousands of benign ones — the hunt is not ready. Go find
the discriminator first; that research is the hunt.

Hypotheses come from: recent intel on actors targeting your sector, ATT&CK
techniques with no detection coverage, crown-jewel assets and the paths to
them, anomalies noticed during other work, and post-incident "what else would
this actor have done."

## Hunting Techniques

### Stack counting (frequency analysis)

The workhorse. Aggregate a field, sort ascending, investigate the rare values.
Malicious activity is usually rare; commodity noise is common.

```sql
-- Splunk: rarest parent-child process pairs
index=sysmon EventCode=1
| stats count dc(host) as hosts by ParentImage, Image
| where count < 10 AND hosts < 3
| sort count
```

```kusto
// KQL: rarely-seen signed binaries making external connections
DeviceNetworkEvents
| where RemoteIPType == "Public"
| summarize Count=count(), Hosts=dcount(DeviceName) by InitiatingProcessFolderPath
| where Hosts <= 2 and Count < 20
| order by Count asc
```

Stack the right field. Stacking `Image` finds unusual binaries; stacking
`ParentImage, Image` finds unusual *relationships*, which is where living-off
the-land abuse shows up (`winword.exe` → `powershell.exe`).

### Outlier analysis

Same shape, different axis: what is normal *for this entity*?

- A service account that has never used interactive logon, now doing so
- A workstation talking to an internal subnet it has never touched
- A user authenticating outside their historical hours and geography
- A host whose process-count baseline shifted after a specific date

```sql
-- Elastic ES|QL: first-seen external destinations per host
FROM logs-network-*
| WHERE destination.ip NOT IN CIDR("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
| STATS first_seen = MIN(@timestamp), n = COUNT(*) BY host.name, destination.domain
| WHERE first_seen > NOW() - 7 days AND n > 20
```

### Grouping and clustering

Cluster on a shared attribute to surface campaigns: same JA3/JA4 across
unrelated hosts, same rare user agent, same certificate serial, same working
hours, same directory of execution.

### Intel-driven hunting

Take a report, extract the TTPs rather than the IOCs, and hunt those. The
report's hashes and IPs are dead; its described behaviour is not.

```
Report says:  "uses schtasks to create a task running a DLL via rundll32"
Bad hunt:     search for the report's hash
Good hunt:    every scheduled task created in the last 90 days whose action
              references rundll32, stacked by task name and DLL path
```

## High-Yield Hunting Grounds

| Hypothesis area | What to look for |
| --- | --- |
| Execution via LOLBins | `rundll32`, `regsvr32`, `mshta`, `certutil`, `bitsadmin`, `msiexec` with network or unusual arguments; `curl`/`wget` piping to a shell on Linux |
| Persistence | Scheduled tasks/cron/systemd units created recently; WMI event subscriptions (rare and almost always malicious); run keys; new services; `authorized_keys` modifications |
| Credential access | LSASS handle opens, `ntds.dit` copies, shadow-copy creation, Kerberos RC4 requests (4769 with encryption type 0x17), DCSync replication rights use |
| Lateral movement | Admin share writes followed by service creation, WinRM/WMI from non-admin hosts, SSH from workstations to servers, RDP chains |
| C2 | Beacon timing regularity, long-lived connections, DNS with high entropy or high subdomain cardinality, TLS with rare JA3/JA4 |
| Exfiltration | Outbound volume outliers per host, archive creation followed by upload, cloud storage domains from servers, DNS TXT volume |
| Identity/cloud | New OAuth grants and consented apps, service principal credential additions, mail forwarding rules, role assignments outside change windows, `StopLogging`/trail deletion |
| Defense evasion | Event log clears (1102/104), Sysmon or EDR service stops, AMSI/ETW patch indicators, timestomping (`$SI` vs `$FN` mismatch) |

## The Hunt Loop

```
1. Hypothesis   (written, with a discriminator)
2. Scope        (data sources, time window, host population — decided up front)
3. Verify       (does the telemetry exist and cover the population?)
4. Query        (broad, then narrow — expect several iterations)
5. Investigate  (every candidate resolved to benign-explained or escalated)
6. Conclude     (found / not found / could-not-determine)
7. Convert      (detection rule, telemetry gap ticket, or documented baseline)
8. Document     (so the next person can re-run it, not re-derive it)
```

**Every hunt produces an artifact, including hunts that find nothing.** A
negative result is a finding when it is documented with its scope and
limitations: "no evidence of X across 4,200 endpoints over 90 days; note that
620 hosts lack the required telemetry." That sentence is worth more than an
undocumented clean bill of health.

## Scoping and Time Windows

- Match the window to dwell-time reality, not convenience. If you look back
  7 days for an actor with a 60-day median dwell time, a clean result is
  meaningless.
- Confirm retention before you commit: a 90-day hunt over 30-day retention
  silently becomes a 30-day hunt.
- Record which host populations are *not* covered by the telemetry you used.
  This is where the next intrusion will live.

## When a Hunt Hits

Stop hunting and switch modes. Preserve first: pull the memory and triage
package before anyone touches the host. Then hand to
`responding-to-incidents` with the query, the raw results, and the timestamp
of your first look — the response team needs to know what you touched and
when, so your own activity does not contaminate the timeline.

Do not "just check one more thing" on a live suspect host. Interactive
commands on a compromised box change evidence and can alert the operator.

## Rationalizations to Reject

- *"Nothing found, so we're clean."* You searched one hypothesis over one data
  set for one window. Write down all three.
- *"Too much data to hunt."* That is what stacking is for. Aggregate first;
  you are looking for the rare, not reading the common.
- *"The EDR would have alerted."* The premise of hunting is that it did not.
- *"That's just noise."* Characterize the noise. "Just noise" is where implants
  hide, and an uncharacterized benign cluster is an unexamined hypothesis.
- *"I'll remember what I searched."* You will not, and neither will your
  successor. Undocumented hunts get repeated instead of extended.
- *"Let me just log into the suspicious host and look."* You are now part of
  the timeline, and possibly a tripwire.
- *"We hunt when we have time."* Ad-hoc hunting produces ad-hoc coverage.
  Schedule hunts against a prioritized technique backlog.

## Deliverable

```markdown
# Hunt: <name>          Date: <UTC>   Analyst: <name>
Hypothesis:             <as written above>
ATT&CK:                 T####.###
Scope:                  <data sources, host population, time window>
Telemetry verified:     <present / partial — name the gaps>
Queries:                <verbatim, so this is reproducible>
Results:                <candidates found, how each was resolved>
Conclusion:             found / not found / could-not-determine
Outputs:                <detection rule ID, telemetry gap ticket, baseline doc>
Limitations:            <what this hunt could not have seen>
```

## References

- `engineering-detections` — converting a successful hunt into a tested rule
- `responding-to-incidents` — the handoff when a hunt confirms compromise
- MITRE ATT&CK for hypothesis generation; PEAK and TaHiTI hunting frameworks
- Sysmon, Zeek, osquery, Velociraptor, and cloud audit logs as core telemetry
