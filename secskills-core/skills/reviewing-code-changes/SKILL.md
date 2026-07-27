---
name: reviewing-code-changes
description: Perform a security review of a diff, branch, or pull request — assessing what the change introduces, weakens, or exposes, with a triage-first workflow and false-positive discipline. Use when asked to security review a PR or branch, check a diff before merge or commit, or assess whether a change is safe to ship.
verified: 2026-07-27
---

# Reviewing Code Changes

Reviewing a diff is not auditing a codebase in miniature. The diff shows you
what changed but hides what the change *means* — the caller that now receives
untrusted data, the check that used to run, the assumption that no longer
holds. Reviewing only the added lines is the standard way to miss the bug.

## When to Use

- Security review of a pull request, branch, or commit range
- Pre-commit or pre-merge check on your own changes
- Assessing risk of a dependency bump or config change
- Reviewing an AI-generated change before it ships

## When NOT to Use

- **Whole-codebase audit** — use `auditing-code-for-vulnerabilities`
- **Runtime testing of the deployed change** — use the relevant testing skill
- **Dependency/CI changes as the main subject** — use `auditing-supply-chain`

## Get the Real Diff First

```bash
# Against the actual merge base, not against whatever HEAD happens to be
BASE=$(git merge-base HEAD origin/main)
git diff --stat $BASE...HEAD
git diff $BASE...HEAD

# Rename and whitespace noise hides real changes
git diff -M -C -w $BASE...HEAD

# Files changed most, and by whom — where to spend attention
git diff --numstat $BASE...HEAD | sort -rn | head -20
```

Three things to establish before reading code:

1. **What is this change trying to do?** Read the PR description and the
   tests. A security review without the intent is pattern matching.
2. **Does the diff match the description?** Unexplained files — a config
   change, a new dependency, a workflow edit riding along with a feature — are
   the highest-signal thing in a review.
3. **What is the change's exposure?** A change to an unauthenticated request
   path deserves an order of magnitude more attention than an internal
   refactor.

## Triage: Where to Spend the Review

Not all diffs deserve equal time. Rank hunks by what they touch:

| Priority | Signals |
| --- | --- |
| **Critical** | Auth/authz logic, session handling, crypto, input parsing on an untrusted boundary, SQL/command/template construction, file path handling, deserialization, CI/CD workflows, IAM/security-group config, dependency additions |
| **High** | New endpoints or routes, new tool/RPC surface, error handling on security paths, logging of user data, tenant scoping, cache keys, rate limits |
| **Medium** | Business logic that consumes validated input, refactors that move security-relevant code |
| **Low** | Tests, docs, formatting, comments — but read test *deletions* |

```bash
# Fast triage of a large diff
git diff $BASE...HEAD --name-only | rg 'auth|login|session|crypto|password|token|admin|permission|\.github/workflows|Dockerfile|terraform|policy'
git diff $BASE...HEAD -U10 | rg -n '^\+.*(eval\(|exec\(|system\(|innerHTML|pickle|yaml\.load|Sprintf.*SELECT|shell=True|verify=False|InsecureSkipVerify)'
```

## What to Look For

### Removals and weakenings — read the minus lines first

The most dangerous diffs delete things. Search the removed lines specifically:

```bash
git diff $BASE...HEAD | rg '^-' | rg -i 'auth|verify|valid|check|sanitiz|escape|permission|assert|csrf|limit'
```

- A validation call deleted "because it was redundant"
- An authorization decorator removed during a refactor
- A test deleted rather than fixed
- A `TODO: add authz` that was never done and is now shipping
- A timeout, size cap, or rate limit removed
- `strict` mode, a security header, or a CSP directive relaxed

### Additions — the ordinary classes, in context

Apply the bug-class hunting from `auditing-code-for-vulnerabilities`, but
scoped to the changed paths: injection sinks, authorization on new object
lookups, SSRF in new outbound calls, path handling on new file operations,
deserialization, secrets, weak randomness, unsafe defaults.

The two questions that catch most real issues in a diff:

> **Does new untrusted data reach an old sink?**
> **Does old untrusted data reach a new sink?**

Both require reading outside the diff.

### Context beyond the diff

Read the whole function for every non-trivial hunk. Then check callers:

```bash
# Who calls the changed function, and do they still satisfy its assumptions?
rg -n 'changedFunctionName\s*\(' --type <lang>
# What else in the codebase uses the pattern this change introduced?
git log -1 --format=%H $BASE  # anchor, then compare behaviour before/after
```

Specifically check whether the change alters an invariant that other code
relies on: a function that used to sanitize and now does not, a return value
whose meaning flipped, a nullable that became non-null, an ordering guarantee
that was dropped.

### Config, infra, and pipeline changes riding along

```bash
git diff $BASE...HEAD -- '*.yml' '*.yaml' '*.tf' 'Dockerfile*' '.github/**' '*.json'
```

- New or bumped dependencies: who maintains them, and does the lockfile change
  match the manifest change? (See `auditing-supply-chain`.)
- Workflow permissions widened, `pull_request_target` added, unpinned actions
- Security group / firewall rules opened, buckets made public, IAM `"*"`
- Debug flags, verbose logging of request bodies, disabled TLS verification
- Feature flags that default to on

### AI-generated and large mechanical changes

Machine-written diffs fail in characteristic ways: plausible-looking
validation that does not actually constrain, error handling that swallows
security-relevant failures, invented API usage that silently no-ops, and
copied patterns applied where the surrounding assumptions differ. For a large
generated diff, sample the security-relevant hunks and verify against the real
library behaviour rather than reading for plausibility.

## Verify Before Reporting

Diff review generates false positives faster than any other review mode,
because the missing context is exactly what makes a hunk look wrong. Before
raising a finding:

1. **Read the surrounding function and the callers.** The check you think is
   missing is often two frames up.
2. **Check the framework's behaviour.** Many "missing escaping" findings are
   handled by the template engine.
3. **Confirm reachability** with the caller privilege required.
4. **Look for the same pattern elsewhere in the codebase.** If it is
   everywhere and predates this PR, it is a codebase finding, not a PR blocker
   — say so, and file it separately.

Then state the finding with a concrete failure scenario: the input, the path,
and the result. "This could be unsafe" is not a review comment; it is a
request for someone else to do the analysis.

## Output

Separate what blocks the merge from what does not:

```markdown
## Security review — PR #482

**Blocking**
1. `api/reports.go:214` — export handler drops the tenant predicate present on
   the list path. Any authenticated user can export another tenant's report by
   ID. Add `AND tenant_id = ?` to the lookup.

**Non-blocking, should fix**
2. `api/reports.go:190` — report IDs are sequential, making enumeration
   trivial once (1) is fixed. Consider opaque IDs.

**Notes / pre-existing**
3. The `findByID` pattern without scoping appears in 14 other handlers and
   predates this PR. Filed as ISSUE-991 rather than blocking here.

**Reviewed but clear**
- New `/webhooks/stripe` route: signature verified before body parse, replay
  window enforced. No finding.
- Dependency bump `lodash 4.17.20 → 4.17.21`: patch for CVE-2021-23337, no
  API change.

**Not covered**
- The React changes under `web/` were not reviewed for XSS in depth; the diff
  touches 40 components.
```

Stating what you reviewed and found clean is as useful as the findings —
it tells the next reviewer where not to spend time, and it makes the coverage
of the review honest.

## Rationalizations to Reject

- *"The diff looks fine."* You reviewed the added lines. Read the removed ones
  and the callers.
- *"CI passed."* CI runs the tests that exist for the behaviour someone
  anticipated.
- *"It's a small change."* One deleted decorator is a small change.
- *"The author is senior."* Review the code.
- *"It's just a refactor."* Refactors move security-relevant code across trust
  boundaries more often than features do.
- *"That's pre-existing."* True, and worth saying — but confirm it is
  pre-existing rather than assuming, and file it rather than dropping it.
- *"I'd need to understand the whole system to be sure."* Then say what you
  could not determine. An honest uncertainty is a reviewable statement; silence
  reads as approval.

## References

- `auditing-code-for-vulnerabilities` — full audit methodology and bug classes
- `auditing-supply-chain` — dependency and workflow changes in the diff
- `securing-ai-systems` — reviewing changes to LLM/agent features
- `reporting-security-findings` — severity and write-up when a finding leaves the PR
