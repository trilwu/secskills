---
name: auditing-code-for-vulnerabilities
description: Audit source code for exploitable vulnerabilities using threat-model-driven review, taint tracing, invariant checking, and variant analysis. Use when reviewing a codebase or diff for security bugs, performing a security audit, hunting for vulnerabilities in a target's source, or validating whether a suspected finding is real.
verified: 2026-07-27
---

# Auditing Code for Vulnerabilities

Finding real bugs in source code is a different job from running a scanner. A
scanner matches patterns; an auditor builds a model of what the code is
*supposed* to guarantee and then hunts for the paths where that guarantee
breaks. This skill is the methodology for the second job.

## When to Use

- Auditing a repository, service, or library for security defects
- Reviewing a diff, branch, or pull request for introduced vulnerabilities
- Hunting for a specific bug class across a large codebase
- Validating whether a scanner finding or a reported vulnerability is real
- Building an audit plan and coverage report for a client engagement

## When NOT to Use

- **Black-box testing of a running app** — use `testing-web-applications` or `testing-apis`
- **Binary-only targets** — use `analyzing-binaries`
- **Dependency and build-pipeline risk** — use `auditing-supply-chain`
- **Cryptographic construction review** — use `reviewing-cryptography`
- **Writing up finished findings** — use `reporting-security-findings`

## The Loop

Auditing is four passes, not one. Do not skip to pass 3.

```
1. Context      → what does this system protect, and from whom?
2. Attack surface → where does untrusted input enter, and what does it reach?
3. Hunt          → trace specific bug classes along those paths
4. Verify        → prove exploitability before you write a word
```

### Pass 1: Build context before reading code

Do not open files at random. Spend the first block of effort answering:

| Question | Where to look |
| --- | --- |
| What are the security-relevant assets? | README, docs, data models, DB schema |
| Who are the actors and trust tiers? | Auth middleware, role enums, tenant models |
| What are the stated invariants? | Tests, assertions, comments containing "must", "never", "invariant" |
| What has already been fixed here? | `git log --grep` for security keywords, CVE files, SECURITY.md |
| What is out of scope? | Engagement brief, vendor code, generated files |

```bash
# Prior security work is the cheapest source of bug leads
git log --oneline --grep='security\|CVE\|vuln\|injection\|auth bypass\|overflow' -i | head -40

# Stated invariants often mark where the author was nervous
rg -n --stats 'MUST NOT|must never|SECURITY|XXX|HACK|TODO.*(auth|secur|valid)' -i

# Where does privilege actually get checked?
rg -n 'is_admin|require_role|authorize|has_permission|@login_required|checkAccess'
```

Write a short target model before hunting: assets, actors, trust boundaries,
and the three invariants whose violation would matter most. Everything after
this is a search for counterexamples to those invariants.

### Pass 2: Map the attack surface

Enumerate *entry points*, then rank them. An entry point matters in proportion
to how far it reaches before it is validated.

```bash
# HTTP/RPC routes
rg -n '@(app|router)\.(get|post|put|delete|patch)|app\.(get|post)\(|@RequestMapping|http\.HandleFunc'

# Deserialization, template rendering, and dynamic execution sinks
rg -n 'pickle\.loads|yaml\.load\(|Marshal|unserialize|ObjectInputStream|eval\(|new Function|exec\(|Runtime\.getRuntime'

# Command, SQL, and path sinks
rg -n 'os\.system|subprocess.*shell\s*=\s*True|child_process\.exec\(|execSync|Statement\.execute|\.raw\(|fmt\.Sprintf.*SELECT'

# Where authentication is decided rather than enforced
rg -n 'verify=False|InsecureSkipVerify|jwt\.decode\(.*verify.*False|algorithms=\[.*none'
```

Rank entry points by: reachable without authentication > reachable by a low
privilege tier > reachable only by an admin. Then follow the highest-ranked
ones inward. Depth beats breadth — one fully traced path is worth twenty
grep hits.

### Pass 3: Hunt bug classes along the traced paths

For each promising path, trace taint from source to sink and ask what the code
assumes. The high-yield classes, in rough order of how often they survive to
production:

**Authorization, not authentication.** Most real breaches are missing object
level checks, not broken login. For every handler that takes an ID, ask: is the
object scoped to the caller's tenant/user, or only looked up by ID? Check the
query, not the decorator.

**Trust-boundary confusion.** Data validated at one layer and re-parsed at
another. Look for values that cross a serialization boundary — a validated
string re-parsed as a URL, a path, a template, or a query.

**State and concurrency.** Check-then-use gaps, non-atomic balance updates,
idempotency keys that are not actually unique, retry paths that replay side
effects. Search for reads followed by writes with no lock or transaction.

**Injection into a secondary interpreter.** SQL, shell, LDAP, XPath, template
engines, log formats, and regex. The question is never "is there a filter" but
"does the filter and the interpreter agree on the grammar."

**Memory safety** (C/C++/unsafe Rust/CGo). Length arithmetic before bounds
checks, `memcpy` with an attacker-influenced size, off-by-one in loop bounds,
signed/unsigned conversions, use-after-free on error paths.

**Error and cleanup paths.** The happy path is usually reviewed; the `except`,
`catch`, `defer`, and `goto fail` branches are not. Audit them specifically.

**Secrets and cryptographic misuse.** Hardcoded keys, non-constant-time
comparison of tokens, predictable IDs from `Math.random`/`rand()`, missing
signature verification. Deep crypto review belongs in `reviewing-cryptography`.

### Pass 4: Variant analysis

A bug is a template, not an incident. When you confirm one, immediately search
for its siblings — the same mistake made by the same author, the same copied
block, the same missing check on a neighbouring route.

```bash
# You found one unscoped lookup. Find every other one.
rg -n 'find_by_id|findOne\(\{ *_id|get_object_or_404' -A3 | rg -v 'tenant|owner|user_id'
```

Variant analysis is where audits produce disproportionate value. Budget time
for it explicitly — roughly one unit of variant search per confirmed finding.

## Verification Before Reporting

A finding you cannot demonstrate is a hypothesis. Before it goes in the report,
answer all four:

1. **Reachability** — name the concrete entry point and the caller privilege
   required. "An attacker who can reach `POST /api/export` unauthenticated."
2. **Control** — show which part of the dangerous value the attacker controls.
3. **Impact** — state what breaks: which invariant from Pass 1, and what an
   attacker gains.
4. **No mitigating control** — check for a WAF rule, a framework default, a
   middleware, a DB constraint, or a caller that already sanitizes.

If a proof of concept is in scope, write the smallest one that proves control
of the sink — not a weaponized exploit.

## Rationalizations to Reject

These are the thoughts that turn an audit into a formality. Each one is wrong.

- *"It's probably validated upstream."* Then go read upstream. Unverified
  assumptions about a caller are the single most common source of missed bugs.
- *"The framework handles that."* Frameworks handle the default path. Check
  the version, check the config, check whether this call uses the safe API.
- *"That input is internal."* Internal today. Trace how it is populated; a
  queue consumer or admin import is usually reachable from outside.
- *"It's only exploitable by an authenticated user."* That is a severity input,
  not a reason to drop the finding.
- *"It looks intentional."* Intent is not a control. Note the intent, keep
  the finding.
- *"The scanner didn't flag it."* Scanners find what they have rules for.
- *"I've reviewed enough files."* Coverage is measured against the attack
  surface you mapped in Pass 2, not against file count.

## Tool Assist, Not Tool Substitute

Static analysis is for coverage and for variant search after you know the
pattern. Write a rule once you have a confirmed bug, and let it find the rest.

```bash
# Semgrep: broad pass, then a rule you write for your specific finding
semgrep --config=auto --severity=ERROR --json -o semgrep.json .
semgrep --config=./rules/my-variant-rule.yaml .

# CodeQL for dataflow questions grep cannot answer
codeql database create db --language=<lang> && codeql database analyze db --format=sarif-latest -o out.sarif

# Language-specific
bandit -r . -f json            # Python
gosec -fmt=json ./...          # Go
cargo audit && cargo geiger    # Rust deps + unsafe surface
npm audit --json               # JS deps
```

Triage every tool finding through the four verification questions above. A
report of unverified scanner output is worse than no report — it burns the
reader's trust and buries the real bugs.

## Audit Deliverable

Track coverage as you go, and state it honestly:

```markdown
## Coverage
| Component | Files | Depth      | Notes                          |
|-----------|-------|------------|--------------------------------|
| auth/     | 12    | Full trace | All routes traced to sinks     |
| billing/  | 30    | Partial    | Webhook handlers only          |
| vendor/   | -     | Excluded   | Out of scope per brief         |

## Findings
F1. [High] Tenant isolation bypass in GET /api/reports/:id — <impact> — <repro>
```

Say what you did **not** cover. An audit that claims full coverage it did not
achieve is the most damaging artifact you can produce.

## References

- `references/bug-class-checklist.md` — per-language hunting checklists
- `reporting-security-findings` — severity scoring and write-up format
- OWASP Application Security Verification Standard (ASVS) for requirement-driven review
- CWE Top 25 and the CWE hierarchy for classification
