---
name: verifying-skill-accuracy
description: Fact-check LLM-drafted technical content against primary sources — source hierarchy, programmatic existence probes for tool and plugin names, class-before-instance error triage, the truncated-negative trap, adversarial re-checking, and the verified-stamp discipline. Use when auditing a SKILL.md for factual errors, before stamping a skill verified, when a command or artifact claim needs confirming against upstream documentation, or when reviewing any drafted content whose specifics were written from model memory.
---

# Verifying Skill Accuracy

Skills in this repo are drafted with LLM assistance. The methodology in them is
usually sound; the **specifics are not trustworthy until checked**. The
measured rate from the first verification pass was **31 factual errors across
11 of 12 skills — about 2.6 per skill**, with a single skill clean on both
passes. Assume that rate applies to anything unstamped.

This skill is the procedure for driving that rate down, and for knowing when
you are allowed to say a skill has been verified.

## When to Use

- Auditing an existing SKILL.md against primary sources
- Before adding or renewing a `verified:` frontmatter stamp
- After drafting new skill content, on the specifics you just wrote
- When a reader reports that a command, ID, or field name does not work
- Reviewing any technical content where the author was a model

## When NOT to Use

- Writing a new skill from scratch — use `authoring-security-skills`, then
  verify with this skill as the final gate
- Structural or style problems (frontmatter, sections, line count) — that is
  `python3 scripts/validate.py --strict`, which checks *form only*
- Deciding whether a technique is a good idea — that is judgment, not fact

## The Core Distinction: Form vs Truth

The repo's CI is a closed loop. `validate.py`, `sync_attack.py`, and
`run_evals.py` check frontmatter shape, cross-reference integrity, ATT&CK-index
consistency, and routing against **self-authored** eval cases. Every one of
those can pass on a skill whose commands do not exist.

> Green CI means the skill is well-formed. It says nothing about whether it is
> true. Never cite a passing test run as evidence of accuracy.

## Triage: Class Errors Before Instance Errors

Do not start by checking facts one at a time. First ask: **is there a single
systematic claim whose failure invalidates everything below it?**

In `analyzing-memory-images`, the skill invoked Volatility as `volatility3`.
The real entry point is `vol`. That one error made **all 40 commands in the
file uncopyable** — far more damage than the two nonexistent plugins found
afterwards, and fixable with one substitution.

Check in this order:

1. **Tool identity** — the binary/entry-point name, and the major version the
   syntax belongs to. Volatility 2 and 3 share almost no command surface.
2. **Naming scheme** — how the tool names its plugins, modules, or subcommands.
   Getting the scheme right validates or invalidates dozens of lines at once.
3. **Path and file conventions** — where artifacts actually live on the version
   in question.
4. **Individual claims** — only now, one by one.

A class error is cheap to fix and expensive to miss. An instance error is the
reverse.

## Source Hierarchy

Use the highest tier available, and record which tier you used.

| Tier | Source | Use for |
| --- | --- | --- |
| 1 | Official docs for the **specific version**, upstream source, RFCs, the vendor's own reference | Command syntax, plugin names, API shapes, protocol details |
| 2 | Vendor KB, release notes, changelogs, official blog announcing a change | Defaults, retention windows, licence gates, deprecations |
| 3 | Maintainer-authored write-ups, conference material by the tool author | Intent, gotchas, why a thing behaves as it does |
| 4 | Community posts, tutorials, Stack Overflow | Leads to verify at tier 1 — **never** as the citation |
| — | Model memory | Nothing. Not one claim. |

Two rules on top of the table:

- **Match the version.** Docs for 2.x do not establish 3.x behaviour. Prefer
  `latest` or `stable` doc branches, and note when the skill targets an older
  pinned release.
- **Ask when it last changed**, not just whether it is true. Vendor defaults
  move: Microsoft's Audit (Standard) retention went 90 → 180 days in October
  2023, and material written before that is now wrong without being obviously
  wrong.

## Never Assert These From Memory

Each of these has produced a real error in this repo:

- CLI entry points and subcommand names
- Plugin, module, and package names
- Version numbers, and any "the default is X" claim
- Event IDs and their exact semantics (4778 is session *reconnect*, not connect)
- Log field and column names
- Retention windows and licence gates
- CVE IDs, CVSS vectors, and affected-version ranges
- API paths, parameter names, required scopes
- **Legal precedent and case outcomes** — a draft in this repo cited Mango
  Markets and Platypus as convictions proving exploitation is prosecuted as
  theft. Both went the other way: the Platypus pair were acquitted in Paris,
  and Eisenberg's Mango convictions were vacated in May 2025. Memory produced
  a confident claim that was backwards.

## Reading Sources: Fetch Markdown, Not HTML

Pull documentation through **`defuddle.md`**, which strips a page to its main
content and returns Markdown with YAML frontmatter. Prefix any URL:

```bash
curl -sL "https://defuddle.md/learn.microsoft.com/en-us/purview/audit-log-retention-policies"
```

The scheme is optional in the path — `defuddle.md/example.com/x` and
`defuddle.md/https://example.com/x` both work.

Two reasons, and the second matters more than the first:

1. **It cuts tokens.** Measured against the pages used in this repo's passes:
   **78%** smaller on a prose doc page (Microsoft Learn), **33%** on a
   link-heavy API index. Prose collapses hard; link tables less so.
2. **It returns the full text, deterministically.** You get the whole page as
   Markdown you can `grep`, instead of a model's summary of the page. That is
   what makes it safe to draw a *negative* conclusion — see below.

Use it for documentation, specs, vendor KB, and articles. Do **not** use it for:

- **JSON or API responses** — readability extraction mangles structured data.
  Fetch those raw.
- **HTTP status probes** — you need the status of the real host, not of a proxy
  that may return 200 for its own error page.
- **Anything internal, client-owned, or target-owned.** The URL leaves your
  machine and goes to a third party. Never route an engagement URL, an internal
  hostname, or a client's estate through an external extraction service. Public
  vendor documentation only.
- **Authenticated or JS-rendered pages** — it fetches as an anonymous client.

**A blocked fetch is not a negative result.** Some hosts refuse the extractor
and return an error blob instead of the page — freedesktop.org answers with
`{"error":"Failed to fetch: 418 I'm a teapot"}`. Treat that as "I did not read
the page", never as "the page does not say this". It is the truncated-negative
trap wearing a different hat, and the fix is the same: re-fetch directly before
concluding anything.

## Programmatic Existence Probes

Where a project publishes one doc page per module, existence is a **status
code**, not a judgment call. This is the highest-confidence, lowest-effort
check available, and it batches.

```bash
# One plugin: 200 = exists, 404 = does not
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.idt.html"

# Every plugin the skill references, in one pass
plugins=$(grep -oE '\b(windows|linux|mac)\.[a-z_]+' SKILL.md | sort -u)
for p in $plugins; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://volatility3.readthedocs.io/en/latest/volatility3.plugins.$p.html")
  [ "$code" = "200" ] || echo "MISSING $code  $p"
done
```

That pass settled 32 plugin references in seconds and found the two that do not
exist. Adapt the URL pattern per project — most doc generators (Sphinx,
mkdocs, pkg.go.dev, docs.rs, npm, PyPI) expose a per-symbol or per-package URL
you can probe the same way.

When a project has no per-symbol docs, fall back to an **exact-string search of
the upstream source** — a raw file fetch and a `grep` for the literal
identifier. Both of these are deterministic. Prefer them over asking any model,
including yourself.

## The Truncated-Negative Trap

**A summarizer saying "not found" is not evidence of absence.**

Fetching a large index page and asking what it contains returned "pslist,
pstree, psaux, sockstat: not listed" for the Volatility Linux plugin index. All
four exist. The page had been truncated before the model saw those entries.
Acting on that output would have *introduced* four errors into a correct
section — verification making the file worse.

The asymmetry that matters:

- **A positive is cheap.** If the tool shows you the identifier, it exists.
- **A negative is expensive.** Absence from a summarized fetch may mean absent,
  truncated, renamed, moved, or paginated away.

So: **never delete or rewrite content on a summarized negative.** Promote every
negative to a deterministic check before you touch the file.

The cheapest promotion is to stop summarizing. Fetch the page through
`defuddle.md` and grep the full Markdown yourself — the answer becomes a match
count rather than a model's recollection:

```bash
L="volatility3.readthedocs.io/en/latest/volatility3.plugins.linux.html"
for p in pslist pstree psaux sockstat; do
  echo "$p: $(curl -sL "https://defuddle.md/$L" | grep -c "linux\.$p module")"
done
# pslist: 1   pstree: 1   psaux: 1   sockstat: 1  -- all four present
```

That is the exact check that refutes the summarizer's "not listed" on all four.
Where a per-symbol URL exists, the status probe below is stronger still. If you
can get neither, leave the content alone and flag it unconfirmed — an
unverified line is recoverable, a confidently deleted correct one is not.

## Consequence Weighting

Not all errors cost the same. Spend effort where failure is silent.

| Failure mode | Example | Cost |
| --- | --- | --- |
| **Loud** — fails on first run | Wrong CLI flag, nonexistent plugin | Minutes. The tool tells you. |
| **Silent** — produces a confident wrong answer | Misread event ID, wrong retention window, wrong artifact meaning | An incident timeline that lawyers read. |

Verify silent-failure claims first and hardest. In practice that means the
defensive and forensic content — event IDs, log schemas, artifact semantics,
retention — outranks offensive tool syntax, even though the offensive content
looks more dangerous.

A concrete case: the M365 skill claimed 90 days of Unified Audit Log for E3.
The real default has been 180 days since October 2023. An analyst trusting the
skill reads an empty 90-day window as "no activity" and closes an investigation
that had six months of history available.

## Procedure

1. **Inventory the checkable claims.** Grep the skill for the classes above —
   commands, identifiers, IDs, field names, numbers with units. Anything that
   could be wrong in a way a reader would not notice.
2. **Resolve class-level claims first** (tool name, version, naming scheme).
   Re-scope everything below to what survives.
3. **Batch-probe every identifier** with a deterministic check.
4. **Verify remaining claims at tier 1 or 2**, recording the source. Pull the
   pages through `defuddle.md` so you are reading full text cheaply rather than
   a summary.
5. **Correct, and say what changed and why** in the commit body — the next
   reader needs to know a claim was checked, not just that a line moved.
6. **Adversarial second pass.** Re-read your corrections trying to *refute*
   them. The original pass over this repo found errors that survived the first
   read and fell on the second; assume yours will too.
7. **Stamp only if complete** — see below.

## The `verified:` Stamp

```yaml
verified: 2026-07-26    # ISO 8601; validate.py parses and counts this
```

The stamp means: **the whole checkable surface of this skill was driven to a
primary source on that date.** It does not mean the skill is good, current
forever, or complete.

Rules:

- **No stamp for a partial pass.** Three defense skills in this repo were
  materially corrected and deliberately left unstamped, because each pass
  covered the dominant claim class but not the whole file. A partial pass
  labelled complete is worse than no label, because it converts an honest
  unknown into a false assurance.
- **Re-stamp on a re-check, not on an edit.** Adding a section does not renew
  the date.
- **Absence is not a defect.** `validate.py` treats a missing stamp as an
  unverified draft, which is the documented default. A malformed date is an
  error because it corrupts the count.

Check the current position any time:

```bash
python3 scripts/validate.py --strict   # prints "Fact-checked ...: N/72"
```

## Rationalizations to Reject

- **"CI passes, so it's fine."** CI checks form. Every error found in this repo
  was in a file with green CI.
- **"I'm confident about this one."** Confidence is uncorrelated with accuracy
  on identifiers and version-specific defaults. The Mango Markets claim was
  written with complete confidence and was backwards.
- **"The tool will error if it's wrong, so the reader will notice."** True for
  syntax, false for interpretation — and interpretation errors are the ones
  that reach a deliverable.
- **"The docs didn't mention it, so I removed it."** A summarized fetch omits
  content constantly. Promote the negative to a status code or an exact-string
  grep before deleting anything.
- **"I'll route everything through defuddle, it saves tokens."** It is for
  public prose. Structured JSON comes back mangled, status probes need the real
  host, and engagement or client URLs must never be handed to a third-party
  service to satisfy a token budget.
- **"It was right when it was written."** Retention windows, licence gates, and
  default paths change under you. Verification is dated for exactly this
  reason; "correct in 2024" is not a defence in 2026.
- **"I fixed the errors I found, so I can stamp it."** You can stamp it when
  you have *looked at everything checkable*, not when you have run out of
  errors you happened to notice.
- **"Close enough — the reader will adapt."** The reader is often a model
  executing the command, or an analyst under incident pressure. Neither adapts.

## References

- `authoring-security-skills` — writing a new skill; verify with this skill
  before stamping
- `CONTRIBUTING.md` — the merge bar and house style
- `scripts/validate.py` — structural checks and the verified-count report
