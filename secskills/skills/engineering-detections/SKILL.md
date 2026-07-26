---
name: engineering-detections
description: Build, test, and tune detection content — Sigma, YARA, Suricata, and EDR/SIEM queries — mapped to MITRE ATT&CK with explicit false-positive analysis and detection-as-code practices. Use when writing or reviewing a detection rule, converting IOCs or TTPs into alerts, measuring detection coverage, or reducing alert fatigue.
---

# Engineering Detections

A detection is a hypothesis about attacker behaviour, expressed as a query,
that a human will be paged for. Two properties decide whether it is worth
deploying: does it fire on the behaviour, and does it stay quiet otherwise.
Most rules fail the second test, and the cost is paid by whoever is on call.

## When to Use

- Writing a new detection rule from a TTP, a sample, or an incident
- Reviewing or tuning an existing rule that is noisy or silent
- Converting threat intelligence into deployable detection content
- Assessing detection coverage against ATT&CK
- Setting up detection-as-code: repo layout, testing, CI, deployment

## When NOT to Use

- **Searching for an unknown compromise right now** — use `hunting-threats`
- **Working an active incident** — use `responding-to-incidents`
- **Analyzing the sample the detection is for** — use `analyzing-malware`
- **Preventive controls and hardening** — hardening is not detection; a rule
  is not a substitute for closing the path

## Detect Behaviour, Not Artifacts

Rank what you write by how expensive it is for the adversary to change:

```
Hash              trivial to change      → block, don't alert
IP / domain       days                   → block + low-severity alert
Filename / path   trivial                → weak signal, combine only
Tooling artifact  weeks (recompile)      → good, decays
Behaviour / TTP   expensive              → this is the target
```

The pyramid-of-pain reasoning is the whole discipline: a rule on
`mimikatz.exe` is worthless; a rule on a process opening a handle to LSASS
with `PROCESS_VM_READ` catches every tool that does the same thing.

## The Rule Development Loop

```
1. Hypothesis   → what behaviour, by whom, visible where?
2. Data check   → is the required telemetry actually collected and retained?
3. Draft        → write the logic against real data
4. FP analysis  → run over 30+ days of production data, characterize every hit
5. Tune         → narrow with attacker-independent conditions only
6. Test         → prove it fires on an emulated true positive
7. Document     → triage steps, response, and known limits
8. Deploy       → with a severity that matches the actual response
9. Review       → re-test after telemetry, environment, or tooling changes
```

Step 2 kills more rules than any other. Before writing logic, confirm the
field exists, is populated on the platforms you care about, and is retained
long enough to matter. A rule on a field your agent does not ship is a
coverage illusion — worse than no rule, because it appears on the map.

## Writing Sigma

Sigma is the portable format; write once, convert per backend.

```yaml
title: LSASS Memory Access from Unusual Process
id: 9f2b1c4e-0000-4000-8000-000000000001
status: experimental
description: >
  Detects a process obtaining a handle to lsass.exe with read/clone access,
  the common precondition for credential dumping regardless of tooling.
references:
  - https://attack.mitre.org/techniques/T1003/001/
author: secskills
date: 2026/07/26
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'   # PROCESS_VM_READ | PROCESS_QUERY_INFORMATION
      - '0x1410'
      - '0x1438'
  filter_legitimate:
    SourceImage|startswith:
      - 'C:\Program Files\<your EDR>\'
      - 'C:\Windows\System32\wbem\WmiPrvSE.exe'
  condition: selection and not filter_legitimate
falsepositives:
  - EDR and backup agents; enumerate yours and filter by full path
  - Windows Error Reporting on crash
level: high
tags:
  - attack.credential-access
  - attack.t1003.001
```

Conversion:

```bash
sigma convert -t splunk -p sysmon rules/lsass_access.yml
sigma convert -t esql -p ecs_windows rules/lsass_access.yml     # Elastic
sigma convert -t kusto -p microsoft_xdr rules/lsass_access.yml  # Defender/Sentinel
```

**Tuning rules that stay honest:** filter on things the attacker cannot
choose. Full paths of signed vendor binaries, specific service SIDs, and
parent-child pairs are acceptable. Filtering on a filename, a username string,
or a command-line fragment the attacker controls is not tuning — it is
building the bypass into the rule.

## Writing Network Detections

```suricata
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Beacon: HTTP POST, no User-Agent, fixed small body";
    flow:established,to_server;
    http.method; content:"POST";
    http.header_names; content:!"User-Agent";
    threshold:type both, track by_src, count 10, seconds 600;
    classtype:trojan-activity;
    metadata:attack_target Client_Endpoint, mitre_technique_id T1071;
    sid:1000101; rev:1;
)
```

For encrypted traffic, detect on metadata rather than content: JA3/JA4
fingerprints, certificate anomalies, SNI/DNS patterns, and — most durably —
**beacon timing**. Regular intervals with jitter are hard for an operator to
give up without losing reliability.

```sql
-- Beacon candidate: low variance in connection interval, sustained
SELECT src_ip, dst_ip, count(*) AS n,
       stddev(delta_seconds) AS jitter, avg(delta_seconds) AS interval
FROM connection_deltas
WHERE ts > now() - interval '7 days'
GROUP BY src_ip, dst_ip
HAVING count(*) > 50 AND stddev(delta_seconds) < 0.15 * avg(delta_seconds)
ORDER BY n DESC;
```

## Writing YARA for Detection at Scale

Rules that run on every file on every endpoint have a different cost profile
from analysis rules. Anchor with cheap conditions first.

```yara
rule Suspicious_Loader_Pattern
{
    meta:
        author = "secskills"
        date   = "2026-07-26"
        scope  = "endpoint scanning"      // vs. hunting/triage
    condition:
        // Cheap gates before expensive string matching
        uint16(0) == 0x5A4D and filesize < 500KB and
        pe.imports("kernel32.dll", "VirtualAlloc") and
        pe.imports("kernel32.dll", "CreateThread") and
        math.entropy(0, filesize) > 7.0
}
```

Always test against a goodware corpus before deployment. A YARA rule with a
0.1% false-positive rate across a million-file fleet is a thousand alerts.

## False-Positive Analysis Is the Job

Never deploy on the strength of "it looked right." The required evidence:

| Check | Threshold |
| --- | --- |
| Historical run over ≥30 days of production data | Every hit characterized, not just counted |
| Alert volume projection | Fits the triage capacity of the team that will receive it |
| Benign-cause enumeration | Each documented in `falsepositives` with a filter or a triage note |
| True-positive test | Fires on an emulated execution of the behaviour |

```bash
# Emulate the behaviour to prove the rule fires
atomic-red-team -T T1003.001              # Atomic Red Team
caldera / prelude operator                 # adversary emulation frameworks
# Then confirm: alert fired, fields populated, triage steps sufficient
```

If a rule cannot be tested because emulating it is unsafe, say so in the
documentation and label the rule unvalidated. Do not let it pass silently as
tested coverage.

## Coverage Measurement

Map rules to ATT&CK, but read the map correctly.

```bash
# Generate a layer for the ATT&CK Navigator from your rule set
python3 scripts/rules_to_navigator.py rules/ > coverage.json
```

Honest coverage accounting:

- A technique is **covered** only if the rule was tested against an emulation
  of it and the required telemetry is collected fleet-wide.
- One rule per technique is not coverage — techniques have many procedures.
  T1055 (process injection) has a dozen materially different implementations.
- Report coverage as tested/untested/no-telemetry, never as a single
  percentage. A green Navigator layer built from untested rules is the most
  common way security teams deceive themselves.

## Detection as Code

```
detections/
├── rules/            # Sigma source of truth, one file per rule
├── tests/            # unit tests: sample events → expected match/no-match
├── filters/          # environment-specific allowlists, kept OUT of the rules
├── deployed/         # generated backend queries (build artifact, never edited)
└── .github/workflows/ci.yml
```

CI should: lint and schema-validate every rule, verify every rule has a unique
`id` and a non-empty `falsepositives`, run unit tests, convert to each target
backend, and fail on conversion errors. Version rules, review them in pull
requests, and keep environment filters separate from detection logic so a rule
can be shared or upstreamed without leaking your environment.

## Rationalizations to Reject

- *"We'll tune it after deployment."* Untuned rules train analysts to close
  alerts without reading them, which is worse than the missing detection.
- *"It's noisy but the analysts can handle it."* Alert fatigue is a security
  control failure with a body count. Measure the volume first.
- *"We have a rule for that technique."* Which procedure? Tested how? On which
  platforms is the telemetry present?
- *"The vendor rule covers it."* Read it. Vendor defaults are tuned for the
  average customer, not your environment.
- *"Add the hash to the rule."* Then the rule is dead on the next build.
- *"We'll filter out that noisy host."* If the exclusion is attacker-reachable,
  you just published a bypass. Filter on properties the attacker cannot assume.
- *"No alerts means we're clean."* No alerts means no alerts. Validate with
  emulation.

## References

- `hunting-threats` — hunts that mature into detections
- `analyzing-malware` — capability analysis that seeds rule logic
- `responding-to-incidents` — incidents that expose detection gaps
- MITRE ATT&CK, Sigma (SigmaHQ), Atomic Red Team, MITRE CAR, Elastic detection rules
- Alerting and Detection Strategy (ADS) framework for rule documentation
