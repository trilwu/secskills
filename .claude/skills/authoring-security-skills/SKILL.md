---
name: authoring-security-skills
description: Write a new SecSkills skill end to end — choosing the plugin bucket and skill tier, writing a description that triggers correctly without stealing traffic from siblings, the required sections, registering the skill in ttp-index.json, adding routing eval cases including negative traps, and running the three validators. Use when adding a skill to this repo, splitting or merging existing skills, fixing a skill that triggers on the wrong requests, or when a new skill fails validate.py, sync_attack.py, or run_evals.py.
---

# Authoring Security Skills

A skill earns its context budget by carrying what the model would otherwise get
wrong. The model already knows what `nmap -sV` does. It does not reliably hold
the *discipline* — trace to demonstrated impact before reporting, preserve
before remediating, refuse to ship a rule never tested against production noise.

That judgment is the deliverable. Commands are scaffolding around it.

## When to Use

- Adding a new skill to `secskills-offense`, `-defense`, or `-core`
- Splitting an overloaded skill or merging two that overlap
- Fixing a skill that loads for the wrong requests, or fails to load for the
  right ones
- Resolving a failure from `validate.py`, `sync_attack.py`, or `run_evals.py`

## When NOT to Use

- Fact-checking content you have written — that is `verifying-skill-accuracy`,
  and it is a separate gate that runs after this one
- Editing prose in an existing, settled skill
- Repo-level work (manifests, marketplace, CI) that is not about a skill

## Step 1: Pick the Plugin

A skill lives in exactly one plugin. The split exists so a blue-team user is
not carrying exploitation content and vice versa.

| Plugin | Takes | Test |
| --- | --- | --- |
| `secskills-offense` | Exploitation, attacker tradecraft, and testing that acts against a target | Would this run against someone's system during an engagement? |
| `secskills-defense` | DFIR, hunting, detection, intel, incident response | Does this read artifacts after the fact, or build detection? |
| `secskills-core` | Dual-use: reverse engineering, code/crypto/supply-chain review, AI security, ATT&CK mapping, reporting | Is it equally at home on both sides? |

When it fits two, choose `core` rather than duplicating. Cross-plugin
references are expected and degrade to inert text for readers who installed
only one plugin — that is by design, so never duplicate a skill to avoid a
cross-reference.

## Step 2: Pick the Tier

**Domain skills** carry methodology for a whole area and trigger on broad,
plain-language requests. Keep them few and non-overlapping.

**Procedure skills** cover one target-and-toolchain combination that is rare,
exact, and unrecoverable from general knowledge — `reversing-flutter-apps`
with blutter, for instance. They are *supposed* to be narrow.

Two rules keep the tiers working:

1. **Every procedure skill is reachable from its domain skill.** Add the
   identifying check and a routing line to the domain skill. An unreachable
   procedure skill is dead weight.
2. **A procedure skill hands back.** Recovering symbols is not the assessment —
   name the skill that continues the work.

Unsure? Ask whether it applies to most engagements in its area (domain) or only
when a specific artifact is in hand (procedure).

## Step 3: Write the Description

**This is the highest-leverage text in the skill.** It is how Claude decides
whether to load it, and it competes with all 71 siblings. A perfect skill body
behind a vague description never runs.

Rules the validator enforces: third person, 60–1024 characters, and a trigger
clause. Rules it cannot enforce but reviewers will:

- Lead with what the skill *does*, then `Use when ...` naming concrete
  situations.
- Build triggers from **what the user actually has in hand** — file names,
  magic bytes, framework and tool names, error strings, the identifying
  symptom. Not abstractions.
- Name the evidence that distinguishes this skill from its nearest sibling.

```yaml
# Good — names artifacts, tools, and the symptom
description: Reverse engineer and intercept traffic from Flutter/Dart mobile
  apps using blutter, reFlutter, and Frida. Use when an APK or IPA contains
  libflutter.so, libapp.so, App.framework, or flutter_assets, when jadx shows
  only a thin Dart wrapper, or when Burp sees no traffic from an app that is
  clearly online.

# Bad — overlaps the domain skill and triggers on the wrong requests
description: Advanced mobile reverse engineering techniques for modern apps.
```

## Step 4: Write the Body

Required sections:

- **`## When to Use`** — concrete situations, not categories.
- **`## When NOT to Use`** — where a different skill is correct, **with the
  sibling named in backticks**. This is what stops skills fighting over the
  same words.

Expected in security skills:

- **`## Rationalizations to Reject`** — the plausible-sounding shortcuts that
  cause missed findings, each with why it is wrong. This is the highest-value
  section in the collection; it encodes judgment a command list cannot.

Offensive skills additionally need **scope and authorization framing** written
to that domain's real exposure — not boilerplate. Recon has third-party estate
and OSINT-as-personal-data; password cracking has account lockout as an
availability risk; RF work has wiretap and spectrum law because you cannot
confine a radio to the target. Generic "get permission first" text is worth
nothing.

**If the skill's workflow reads public reference material** — advisories,
specs, RFCs, vendor reports, ATT&CK pages — include the standard
`## Reading External Sources` block before `## References`. Copy it verbatim
from a skill that has it (`producing-threat-intelligence`,
`auditing-supply-chain`); it must stay identical across skills so it does not
drift. It routes public documentation through `defuddle.md` for a large token
saving and full greppable text.

Do **not** add that block to a skill whose network activity is aimed at a
target. Cloud metadata endpoints, the target's own services, exfil hosts,
phishing URLs, and C2 must be fetched directly — routing them through a
third-party extractor breaks the command, leaks engagement URLs, and for live
adversary infrastructure tips off the operator.

**Order steps by when they happen, and say so.** A skill body that reads as an
unordered pile of techniques gets sampled, not followed. Mark the first actions
as immediate, the ones that depend on their output as following, and the ones
that touch the target as acting — then a reader who loads the skill mid-task
knows where they are. The ordering also carries the safety property: anything
in the acting group is gated on authorization being granted, which is only
legible if the groups are distinguishable.

**A skill is a set of instructions to carry out, not a document to acknowledge.**
Loading one and replying that it has been read and understood is a failure
mode worth naming in the body when the first step is easy to skip — a skill
whose opening move is "record scope before touching anything" is exactly the
skill a hurried reader will summarise instead of doing.

Write for judgment, not recall:

| Write this | Not this |
| --- | --- |
| Why one technique is chosen over another, and when it fails | A list of tool flags |
| The verification a finding must survive before being reported | "Report the vulnerability" |
| Where the discipline goes wrong, named explicitly | Generic best-practice reminders |

Keep `SKILL.md` under 600 lines; move payload lists and long tables into a
`references/` directory, which loads only when pointed at. Do not chain them:
SKILL.md may point at a reference file, but that file must not send the reader
on to a third one.

Note that the validator resolves every backtick-quoted reference path as a real
file — so an illustrative path in prose will fail the build. Name real files
only.

## Step 5: Register in the ATT&CK Index

**`sync_attack.py` fails if a skill is neither mapped nor declared unmapped.**
Edit `secskills-core/ttp-index.json`, never the generated block in a SKILL.md.

Map it — add the skill to the `skills` array of each technique it covers:

```json
{"id": "T1595", "name": "Active Scanning", "tactics": ["TA0043"],
 "skills": ["performing-reconnaissance", "enumerating-network-services"]}
```

Or declare why Enterprise ATT&CK does not apply:

```json
"_unmapped": {
  "securing-ai-systems": "MITRE ATLAS (AML.T####) and the OWASP Top 10 for LLM / Agentic Applications"
}
```

Then regenerate — the `## ATT&CK Coverage` block is generated, so hand-editing
it is always wrong:

```bash
python3 scripts/sync_attack.py --write
```

## Step 6: Add Eval Cases

Routing is a real failure mode; the eval set is how it is caught. Add cases to
`evals/cases.jsonl` — one JSON object per line:

```json
{"id": "adcs-esc1-certipy-vuln-template",
 "query": "certipy find -vulnerable flagged a template with ENROLLEE_SUPPLIES_SUBJECT and low-priv enrollment — how do I turn this into domain admin?",
 "expect_skill": "abusing-adcs",
 "also_acceptable": ["attacking-active-directory"],
 "expected_behavior": ["Identify this as an ESC1 escalation path",
                       "Request a cert specifying an alternate UPN",
                       "PKINIT with the cert to obtain the target's TGT/NT hash"],
 "trap_for": ["attacking-active-directory", "attacking-kerberos-delegation"]}
```

Write the `query` as a real user would type it — with the tool output, the
error, the artifact in hand. Sanitised queries prove nothing.

**`trap_for` is the important field.** It lists the skills this query must
*not* route to. Every new skill should appear in the `trap_for` of at least one
neighbour's case, and carry at least one case of its own that traps against its
nearest neighbours. That is the only mechanical pressure against description
creep.

## Step 7: Validate

All three must pass before a PR:

```bash
python3 scripts/validate.py --strict     # form, manifests, verified count
python3 scripts/sync_attack.py --check   # ATT&CK blocks match the index
python3 scripts/run_evals.py --check     # every skill covered, no bad refs
```

Then bump the version in the plugin's `.claude-plugin/plugin.json` **and**
`.claude-plugin/marketplace.json` — the validator enforces agreement — and add
a `CHANGELOG.md` entry. Update the plugin description's skill count if the
count changed; `validate.py` warns when it drifts.

## Step 8: Do Not Stamp It Verified

New content is an unverified draft by definition. **Never add a `verified:`
date to a skill you just wrote.** Hand it to `verifying-skill-accuracy`, drive
every checkable claim to a primary source, and stamp only if you covered the
whole surface.

Passing all three validators is not verification. They check form; the first
verification pass over this repo found 31 factual errors in files with green
CI.

## Rationalizations to Reject

- **"The description is close enough; the body is what matters."** A skill that
  never loads has no body. Description quality is the single largest
  determinant of whether the work gets used.
- **"I'll make the description broad so it definitely triggers."** Broad
  descriptions steal traffic from precise siblings and get the *wrong* skill
  loaded for real work. Precision is what makes the collection compose.
- **"This overlaps an existing skill, but mine covers it better."** Then fix
  the existing skill. Two skills competing for the same query degrades both.
- **"It's mostly commands — the discipline is obvious."** If it were obvious it
  would not need writing down. Command catalogues are what the model already
  has; the judgment is what it lacks.
- **"I'll add the ATT&CK block by hand, it's faster."** It is generated.
  Hand-edits are overwritten on the next sync and fail `--check` until then.
- **"Evals are a formality."** Routing errors are the most common real failure
  in a large collection, and `trap_for` cases are the only thing that catches a
  description quietly widening.
- **"I tested the commands, so it's verified."** Testing on your box confirms
  they run there, not that identifiers, defaults, and IDs are correct on the
  versions readers have. That is a separate pass.

## References

- `verifying-skill-accuracy` — the fact-checking gate that runs after this
- `CONTRIBUTING.md` — the merge bar, house style, and PR expectations
- `secskills-core/ttp-index.json` — the technique-to-skill map
- `evals/README.md` — the eval harness and case format
