---
name: mapping-attack-techniques
description: Navigate security work by MITRE ATT&CK tactic and technique — resolve a technique ID or name to the right skill, map a threat intel report or adversary emulation plan to procedures, and run the purple-team loop from technique to detection to validation. Use when a request names an ATT&CK ID like T1003.001, a tactic like lateral movement, an APT group or intel report, or when planning coverage against the matrix.
---

# Mapping ATT&CK Techniques

ATT&CK is a shared vocabulary, not a methodology. Its value is that offense,
detection, and response can name the same behaviour — which makes this skill a
router, not a technique catalogue. It resolves a technique to the skill that
holds the actual procedure, and it runs the loop that connects the two sides.

## When to Use

- A request names a technique ID (`T1003.001`), a technique name
  ("Kerberoasting"), or a tactic ("we need lateral movement coverage")
- Converting a threat intel report or an adversary emulation plan into work
- Planning or reporting coverage against the matrix
- Running a purple team exercise: emulate, detect, validate, close the gap
- Choosing which skill applies when a request spans offense and defense

## When NOT to Use

- **A plain-language request** ("dump creds off this host") — the domain skills
  trigger directly on that; routing through here adds a hop for nothing
- **Code-level vulnerability work** — ATT&CK does not model source defects; use
  `auditing-code-for-vulnerabilities` with CWE and ASVS instead
- **AI/LLM systems** — use `securing-ai-systems`; the framework there is MITRE
  ATLAS, not ATT&CK Enterprise
- **Mobile targets** — `testing-mobile-applications`; the Mobile matrix has its
  own IDs that do not correspond to Enterprise ones

## The Index

`secskills/ttp-index.json` maps techniques to the skills that cover them. Read
it directly to resolve a lookup:

```bash
# Which skill covers this technique?
python3 -c "
import json;d=json.load(open('secskills/ttp-index.json'))
print([r for r in d['techniques'] if r['id']=='T1003.001'])"

# Everything under one tactic
python3 -c "
import json;d=json.load(open('secskills/ttp-index.json'))
[print(r['id'], r['name'], '→', ', '.join(r['skills']))
 for r in d['techniques'] if 'TA0008' in r['tactics']]"

# Search by name when you have words, not an ID
rg -i 'kerberoast|pass the hash' secskills/ttp-index.json
```

Each skill also carries a generated `## ATT&CK Coverage` section listing its
techniques. That section and the index are kept in sync by
`scripts/sync_attack.py`; the index is the source of truth.

**Three things the index deliberately does not do.** It does not claim
coverage of every technique — the `_unmapped` block names the skills that use
a different framework and says which. It does not repeat detection and hunting
on every row, because those apply to all of them. And it is hand-curated, so
technique IDs drift as ATT&CK releases new versions: re-verify against
[attack.mitre.org](https://attack.mitre.org) before citing an ID in a report.

## Resolving a Request

```
Technique ID or name  → look up in the index → load the named skill
Tactic               → list the tactic's techniques → ask which procedure
Intel report         → extract TTPs (not IOCs) → map each → prioritize by
                       what your environment actually exposes
Group / APT name     → pull the group's technique list from ATT&CK → intersect
                       with your attack surface → hunt the intersection
```

**Techniques are not procedures.** T1055 (Process Injection) has a dozen
materially different implementations, and a detection for one catches none of
the others. When a request arrives as a bare technique ID, the useful next
question is *which procedure* — the specific API sequence, tool, or command
variant. Answering "we cover T1055" without naming a procedure is the most
common way ATT&CK is used to mislead.

## The Purple Team Loop

This is what the shared vocabulary is for. Each step hands to a different
skill, and the technique ID is what keeps them talking about the same thing.

```
1. Select    → pick a technique by threat relevance, not matrix tidiness
2. Emulate   → run the procedure (offensive skill, or Atomic Red Team)
3. Observe   → did telemetry capture it? which data source, which fields?
4. Detect    → write the rule against the behaviour  → engineering-detections
5. Validate  → re-run the emulation; confirm the alert fires and is triageable
6. Hunt      → search historically for prior instances → hunting-threats
7. Record    → tested / untested / no-telemetry, per technique
```

Step 3 is the one that produces the real finding. A technique that executes
with no telemetry at all is a visibility gap, and that outranks a missing rule
— you cannot write a detection for data you do not collect.

Select techniques by relevance: what actors targeting your sector actually
use, what your crown-jewel assets are reachable through, and where you already
suspect a gap. Working left-to-right across the matrix produces even coverage
of things nobody does to you.

## Coverage Reporting

Report per technique in three states, never as a single percentage:

| State | Means |
| --- | --- |
| **Tested** | Emulated, telemetry confirmed present fleet-wide, rule fired, triage steps exist |
| **Untested** | A rule exists but has never been validated against an emulation |
| **No telemetry** | The data source is not collected, or not on all platforms |

A green ATT&CK Navigator layer built from untested rules is the most common
self-deception in security programs. If you generate a layer, encode the three
states as distinct colours and say in the legend what each means.

```bash
# Navigator layer from the index (coverage claimed, not coverage tested)
python3 -c "
import json;d=json.load(open('secskills/ttp-index.json'))
print(json.dumps({'name':'SecSkills skill coverage','versions':{'layer':'4.5'},
 'domain':'enterprise-attack',
 'description':'Skills that cover each technique. Claimed, not validated.',
 'techniques':[{'techniqueID':r['id'],'comment':', '.join(r['skills']),'score':1}
   for r in d['techniques']]}))" > coverage-layer.json
```

Label any generated layer as *claimed* coverage. Turning it into *tested*
coverage requires the loop above, one technique at a time.

## Rationalizations to Reject

- *"We cover that technique."* Which procedure, validated how, with which
  telemetry, on which platforms?
- *"Let's get coverage across the whole matrix."* Even coverage is a
  misallocation. Prioritize by what is actually used against you.
- *"The technique ID is in the rule's tags, so it's mapped."* Tagging is not
  testing.
- *"ATT&CK doesn't have an ID for this, so it's out of scope."* The matrix is
  a model of observed behaviour, not a boundary. Code-level bugs, AI system
  attacks, and Web3 exploits have no Enterprise IDs and still matter — say
  which framework you used instead.
- *"The intel report lists these IOCs, so hunt those."* Hunt the TTPs. The
  hashes and IPs in a published report are already dead.
- *"We emulated it and nothing alerted, so the rule is broken."* Check
  telemetry first. Usually the data was never collected.

## References

- `engineering-detections` — writing and validating the rule for a technique
- `hunting-threats` — historical search for a technique in your environment
- `responding-to-incidents` — mapping observed attacker activity to techniques
- `secskills/ttp-index.json` — the technique-to-skill index this skill reads
- MITRE ATT&CK, ATT&CK Navigator, Atomic Red Team, CALDERA, MITRE ATLAS (AI)
