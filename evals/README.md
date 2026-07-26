# Evaluations

Anthropic's skill-authoring guidance is blunt about this: *evaluations are your
source of truth for measuring skill effectiveness*, and you should build them
early rather than document imagined behaviour. For a collection this size — 59
skills, many with deliberately overlapping subject matter — the failure mode
that matters is **routing**: the right skill has to activate on its trigger, and
it has to stay quiet when a sibling owns the request.

`cases.jsonl` holds that contract as data. Each line is one realistic user
request labelled with the skill that should handle it.

## Case schema

Extends Anthropic's eval example (`{skills, query, expected_behavior}`) with the
routing fields this collection needs:

```json
{
  "id": "grpc-opaque-binary-body",
  "query": "Burp shows an opaque binary request body and the response is HTTP/2 with content-type application/grpc. How do I test this?",
  "expect_skill": "attacking-grpc-protobuf",
  "also_acceptable": ["testing-apis"],
  "expected_behavior": [
    "Recovers the .proto schema (reflection, client descriptors, or decode_raw) before testing",
    "Does not treat it as a generic binary to reverse"
  ],
  "trap_for": ["analyzing-binaries", "testing-apis"]
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Unique, descriptive, kebab-case |
| `query` | yes | The user request, phrased naturally, containing the real trigger (artifact, symptom, or tool) |
| `expect_skill` | yes | The skill that should activate — spelled exactly as its directory |
| `expected_behavior` | yes | 2-3 short strings describing what a correct response does first |
| `also_acceptable` | no | Sibling skills that would also be a reasonable route |
| `trap_for` | no | Skills whose triggers this query superficially resembles but must **not** win — the negative tests |

`trap_for` cases are the point of the harness. Two skills that both mention
"binary" or "cloud" or "container" will fight over the same words; a trap case
is how you prove the disambiguation in each skill's `When NOT to Use` actually
holds.

## Running

The runner is deterministic and needs no network or model. It checks the eval
set is well-formed and that **every shipped skill is exercised** by at least one
case:

```bash
python3 scripts/run_evals.py --check    # CI: structural integrity + full coverage
python3 scripts/run_evals.py --report   # per-skill coverage table
```

`--check` fails if a case references a skill that does not exist, an `id` is
duplicated, a `trap_for` names the expected skill, or any skill has zero cases.
CI runs it on every push.

## Judging the queries (the live loop)

Structural validity is not the same as correct routing. To measure routing,
run the queries against a fresh Claude with the plugin loaded ("Claude B" in
Anthropic's terminology) and confirm that:

1. `expect_skill` (or an `also_acceptable` skill) is the one that activates.
2. No skill listed in `trap_for` activates.
3. The response's opening moves match `expected_behavior`.

A query that routes to a `trap_for` skill is a real defect — usually a
`description` that claims too much or a missing line in a sibling's
`When NOT to Use`. Fix the skill, not the eval.

## Adding a skill

Every new skill must ship with at least one case here, or `--check` fails. Add a
positive case on its trigger, and — if it lives near an existing skill — at
least one `trap_for` case proving the boundary.
