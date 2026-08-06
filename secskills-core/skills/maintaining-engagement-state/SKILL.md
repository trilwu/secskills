---
name: maintaining-engagement-state
description: Keep the durable record that outlives a session — credential provenance, access inventory, artifacts left on target for cleanup, findings with evidence, and a dead-end log — so work spanning days or analysts does not restart or contradict itself. Use when an engagement or investigation runs longer than one sitting, when resuming work after a gap, when handing off to another analyst, before a context window rolls over, or when you cannot say where a credential or access came from.
verified: 2026-07-27
---

# Maintaining Engagement State

An engagement lasts weeks. A session does not. The gap between those two facts
is where work gets repeated, findings lose their evidence, credentials become
unattributable, and artifacts get left on production because nobody wrote down
that they were placed.

This is not administrative overhead bolted onto the real work. **Provenance is
what makes a finding reportable, and the artifact register is what makes
cleanup possible.** Neither can be reconstructed afterwards from terminal
scrollback.

Assume everything not written to the record is lost: not merely forgotten, but
*silently* lost, so the next session confidently redoes it or contradicts it.

## When to Use

- Any engagement or investigation continuing past a single sitting
- Resuming after a break, or picking up someone else's work
- Approaching a context boundary with unrecorded state
- Handing off between analysts, shifts, or teams
- Before running anything that writes to a target
- When you cannot answer "which host did this credential come from?"

## When NOT to Use

- **Writing the client-facing deliverable** — use `reporting-security-findings`;
  this skill produces the raw material that skill consumes
- **Deciding whether a finding is real** — that is the relevant testing or
  analysis skill; record the outcome here either way
- **Chain of custody for evidence that may reach court** — legal custody has
  formal requirements beyond this; use `responding-to-incidents` and follow
  the organisation's counsel
- **A single self-contained task** finished in one sitting with nothing left
  on target

## The Six Records

Keep these in one file, in the repository or case folder, updated as you go —
not reconstructed at the end.

### 1. Scope and authorization

In-scope targets and explicit exclusions, the testing window, the named
contact, and where the authorization letter lives. Copy the exclusions
verbatim; paraphrasing scope is how people test the wrong estate.

Record one more field, because "in scope" and "reachable" are different
questions. **Egress mode** says what this engagement is allowed to talk to:

| Mode | Allowed | Refused |
| --- | --- | --- |
| `offline` | Static analysis, local samples, emulation | Any outbound packet |
| `lab_only` | Lab and VM ranges you control | Production, anything routable |
| `authorized_target_only` | Assets named in scope | Everything not on the list |
| `unrestricted_lab` | Isolated lab network, in writing | The public internet |

Name the mode before the first command, not after something reaches further
than you meant. It is the field that catches the two classic mistakes: a
"static-only" malware triage that resolves a C2 domain, and a scoped web test
whose scanner follows a redirect off-estate. When a skill in this repo says an
action needs an isolated lab, it means `lab_only` or stricter.

Authorization is a gate, not a note. If authorization is pending or absent,
reading documentation and planning are fine; scanning, hooking, and
exploitation are not.

### 2. Credential provenance

For every credential, hash, token, or key: **what it is, where it came from,
how it was obtained, and what it has been used against.**

```
cred-04  | svc_backup NTLM hash
         | source: SAM dump, WS-014 (10.2.3.14), local admin via CVE-2021-XXXX
         | obtained: 2026-07-27 14:02
         | used on: FS-02 (success), DC-01 (failed, no local admin)
         | provenance: CONFIRMED
```

Provenance is not bookkeeping. It answers three questions you will be asked:

- **Is it real?** Credentials of unknown origin may be planted — see
  `recognizing-deception`. If you cannot say where it came from, you cannot
  rule that out.
- **Was it in scope?** A credential harvested from an out-of-scope host taints
  everything reached with it.
- **What is the blast radius?** The client's remediation is "rotate these
  specific secrets", which requires the list.

Mark anything you cannot trace as `provenance: UNKNOWN` and treat it as
suspect rather than quietly using it.

### 3. Access inventory

Each access obtained: host, account, privilege level, the method, and whether
it still works. Access decays — sessions die, passwords rotate, hosts reboot.
A list of what you *had* is not a list of what you *have*.

### 4. Artifact register — the cleanup list

**Every write to a target, recorded at the moment you make it.** Files
dropped, services or tasks created, accounts added, registry keys, shares,
firewall rules, cloud resources, config edits.

```
art-07 | WS-014 | C:\Windows\Temp\c2.exe        | dropped 14:02 | REMOVED 18:40
art-08 | DC-01  | scheduled task "WinUpdateSvc" | created 15:10 | PENDING
art-09 | AWS    | IAM user "svc-audit-tmp"      | created 16:22 | PENDING
```

Written afterwards from memory, this list is always incomplete, and what it
omits is left on the client's production estate. Two independent parties need
it: you, to clean up; and the client's blue team, to distinguish your
artifacts from a real intrusion — during and after the engagement.

For an incident investigation the same register covers what *you* touched on
evidence systems, so your activity is separable from the adversary's.

### 5. Findings with evidence

Each finding: what, where, the reproduction steps, the evidence captured, and
the impact demonstrated. Capture evidence **when you see it** — the state that
proved it will not survive remediation, a reboot, or a rotated credential.

### 6. Dead ends

The record most often skipped and most valuable across sessions: what was
tried, against what, and why it failed.

```
dead-03 | Kerberoast svc_sql | hash cracked? NO after 6h, 14M candidates
dead-04 | SMB signing DC-02  | enforced -- relay not viable
dead-05 | /admin on portal   | 403 from all tested source ranges
```

Without this, the next session re-runs the six-hour crack. Recording negative
results is also the difference between "we found nothing there" and "we did
not look" in the final report.

## Session Boundary Discipline

Before a session ends — planned or not — the record must answer:

1. What access do I currently hold, and does it still work?
2. What have I left on target that is not yet cleaned up?
3. What was I in the middle of?
4. What did I rule out, so nobody repeats it?

Write these down *as you work*, not at the end. The session that ends
unexpectedly is precisely the one whose state was never captured, and an
engagement can lose its context without warning.

## Handoff

A handoff is the same record plus three additions: current position, the
immediate next action, and anything time-sensitive (a running crack, an
expiring token, a scheduled task that fires at 02:00). If the receiving
analyst has to ask "what were you doing?", the handoff failed.

## Across Engagements

The six records reset each engagement. Two things are worth carrying between
them, and both fail the same way — reconstructed from memory, they are wrong.

**What the machine can actually do.** Before a skill runs a tool, the tool has
to exist, at a known path, at a version whose flags match what the skill
assumes. Guessing `/usr/bin/ghidra` or `jadx` and debugging the failure as if
it were the target's fault is a standard way to lose an hour. Keep a local,
machine-specific inventory — tool, real path, version, and for anything that
speaks over a socket (an MCP server, a helper daemon) whether it is not just
installed but *registered and answering*. Present and ready are different
states: an MCP binary on disk with no running server is not a capability. This
inventory is per-machine and does not belong in a shared repo; treat it the way
you treat `~/.ssh/config` — yours, gitignored, assumed by nothing you publish.

**What past cases taught.** A short, de-identified journal entry per finished
case — the scenario, the technique that worked, the dead ends and the hours
they cost, the tooling surprise — turns the next similar case from a cold start
into a lookup. Keep an index over the entries by scenario, by technique, and by
target trait, and read *that* before starting new work, not the entries
themselves; the index is the cheap part. Seed it with a handful of worked
reference cases so it is useful on day one rather than after the tenth
engagement.

Two disciplines make the journal safe to keep. **De-identify at write time**,
not before sharing — real domains, IPs, tokens, and PII become placeholders the
moment the entry is written, so an entry that is never meant to leave still
cannot leak if it does. And **keep it local by default**: contributing lessons
to a shared or public location ships engagement detail to a third party, and
"the model anonymised it" is not a control you would defend to a client. If a
journal is ever shared, that is a deliberate, reviewed decision per entry — not
a default step in the workflow.

## Rationalizations to Reject

- *"I'll remember where that came from."* You will not, and neither will the
  next session. Unattributable credentials are unusable in a report and
  indistinguishable from planted ones.
- *"It's all in my terminal history."* History has no reasoning, no timestamps
  you can trust, no failures, and no record of what you concluded. It is also
  routinely lost with the session.
- *"I'll write the cleanup list at the end."* The end is exactly when memory is
  worst and the list is longest. Artifacts written from memory are always
  incomplete, and the omissions stay on production.
- *"Nobody needs my dead ends."* They are the difference between a reported
  negative result and an unexamined gap, and they stop the next session
  spending six hours re-cracking the same hash.
- *"I'll clean up as I go, so no register is needed."* Then the register costs
  you one line per artifact and proves it. Without it you cannot demonstrate
  the estate was returned to its prior state.
- *"The client only wants the findings."* Until an alert fires next month and
  they need to know whether the account you created was yours. Unclaimed
  artifacts get investigated as intrusions.
- *"Recording failures makes the engagement look weak."* An engagement with no
  recorded negatives looks unmethodical, not successful. Coverage is a finding.

## References

- `reporting-security-findings` — consumes this record to produce the
  deliverable
- `recognizing-deception` — why unattributable credentials are dangerous, not
  merely untidy
- `responding-to-incidents` — the investigation-side equivalent, including
  formal evidence handling
