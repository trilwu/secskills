# Contributing to SecSkills

Thanks for contributing. This document is the quality bar for what gets merged.

## Ground rules

- Contributions must serve authorized security work: assessments with
  permission, defensive operations, research in controlled environments, CTFs,
  and education.
- No working malware, implants, loaders, packers, or evasion tooling. Skills
  may describe attacker techniques in the detail needed to test or detect them;
  they may not be a build kit.
- Cite sources for techniques. Test commands before submitting them.

## Run the validator before opening a PR

```bash
python3 scripts/validate.py --strict
```

CI runs the same check. It verifies frontmatter, kebab-case naming,
directory/name agreement, description quality, required sections, referenced
files, agent manifest consistency, and manifest version agreement.

## Skill layout

```
secskills/skills/<skill-name>/
├── SKILL.md              # required; keep under 600 lines
├── references/           # optional; detail loaded on demand
└── scripts/              # optional; runnable helpers
```

The directory name and the frontmatter `name` **must** match. Use gerund form
where it reads naturally — `auditing-code-for-vulnerabilities` rather than
`code-audit-tool`.

## Frontmatter

```yaml
---
name: analyzing-malware
description: Analyze suspected malware safely — containment, static triage,
  sandboxed detonation, unpacking, capability and C2 extraction, IOC
  production, and YARA rule authoring. Use when handed a suspicious file,
  hash, or sample, when triaging an alert artifact, or when producing
  detection content from a specimen.
---
```

The description is how Claude decides whether to load the skill, and it
competes with every other skill in the session. Write it in third person, lead
with what the skill does, and include an explicit trigger clause ("Use when
...") naming concrete situations. Keep it under 1024 characters.

## Two kinds of skill

The collection has two tiers, and knowing which one you are writing decides
how you write the description.

**Domain skills** carry methodology and judgment for a whole area —
`auditing-code-for-vulnerabilities`, `responding-to-incidents`,
`testing-mobile-applications`. They trigger on broad, plain-language requests.
There should be few of them, and their scopes must not overlap; that is what
`When NOT to Use` is for.

**Procedure skills** cover one specific target-and-toolchain combination that
comes up rarely, needs an exact sequence, and is unrecoverable from general
knowledge — `reversing-flutter-apps` (blutter), `reversing-unity-il2cpp`
(Il2CppDumper), `reversing-react-native-apps` (hbctool). These are *supposed*
to be narrow. A generic mobile skill cannot hold the blutter workflow without
bloating for every reader who is not looking at a Flutter app, and a reader
who *is* looking at one needs far more detail than a generic skill would ever
carry.

Procedure skills do not compete with domain skills for triggering, provided
the description names the identifying evidence:

```yaml
# Good: names the artifacts, the tools, and the symptom
description: Reverse engineer and intercept traffic from Flutter/Dart mobile
  apps using blutter, reFlutter, and Frida. Use when an APK or IPA contains
  libflutter.so, libapp.so, App.framework, or flutter_assets, when jadx shows
  only a thin Dart wrapper, when Burp sees no traffic from an app that is
  clearly online, or when the target is built with Flutter.

# Bad: overlaps the domain skill and triggers on the wrong requests
description: Advanced mobile reverse engineering techniques for modern apps.
```

Write the description around **file names, magic bytes, framework names, tool
names, and the symptom that identifies the situation**. Those are what a user
actually has in hand, and they make the skill unambiguous.

Two rules keep the tiers working:

1. **Every procedure skill is reachable from its domain skill.** Add the
   identifying check and a routing table to the domain skill, so a user who
   starts generic lands in the right place. An unreachable procedure skill is
   dead weight.
2. **A procedure skill hands back when it is done.** Recovering symbols is not
   the assessment — say which skill continues the work.

If you are unsure which tier you are writing: does it apply to most engagements
in its area (domain), or is it the thing you only reach for when a specific
artifact is present (procedure)?

## Required sections

Every SKILL.md has:

- **`## When to Use`** — concrete situations
- **`## When NOT to Use`** — where a different skill or approach is correct,
  with the alternative named. This prevents the skill from being loaded for
  work it will handle badly.

Security skills should also have:

- **`## Rationalizations to Reject`** — the plausible-sounding shortcuts that
  cause missed findings, each with why it is wrong. This is the highest-value
  section in most of our skills; it encodes judgment that a command list
  cannot.

## Write for judgment, not recall

The model already knows what `nmap -sV` does. A skill earns its context budget
by teaching what the model would otherwise get wrong:

| Write this | Not this |
| --- | --- |
| Why one technique is chosen over another, and when it fails | A list of tool flags |
| The verification a finding must survive before being reported | "Report the vulnerability" |
| Where the discipline typically goes wrong, named explicitly | Generic best-practice reminders |
| Trade-offs and judgment calls with the decision criteria | Exhaustive command catalogues |

Prefer a short, sharp skill over a long, comprehensive one. Move reference
material — payload lists, per-language checklists, tables — into
`references/`, which loads only when the skill points at it.

Avoid reference chains: `SKILL.md` may point to `references/x.md`, but
`references/x.md` should not send the reader to a third file.

## Cross-reference other skills

Name the sibling skill in backticks when handing off (`` `analyzing-binaries` ``).
This is how the collection composes instead of overlapping.

## Agents

```
secskills/agents/<agent-name>.md
```

The filename and frontmatter `name` must match, and the agent must be listed
in `.claude-plugin/plugin.json`. Use `model: inherit` unless the agent has a
specific reason to pin a model. Keep agents thin: they set the role, the
operating rules, and the reporting format, then delegate methodology to the
skills they reference.

## Versioning

`.claude-plugin/plugin.json` and `.claude-plugin/marketplace.json` must carry
the same version, and it must be bumped for users to receive updates. The
validator enforces agreement. Add a `CHANGELOG.md` entry for anything
user-visible.

## Pull requests

- One skill or one coherent change per PR.
- State what you tested and on what.
- If you add a technique, link the source.
