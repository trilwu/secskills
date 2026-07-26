#!/usr/bin/env python3
"""Trigger-accuracy evaluation harness for SecSkills.

Anthropic's authoring guidance treats evaluations as the source of truth for a
skill's effectiveness: a skill is only as good as its ability to be *selected*
when it should be and to be *left alone* when it should not. This harness holds
that contract as data.

Each case in `evals/cases.jsonl` is one realistic user request labelled with the
skill that should handle it. The schema extends Anthropic's eval example
(`{skills, query, expected_behavior}`) with the routing fields this collection
needs:

    {
      "id": "grpc-binary-body",
      "query": "Burp shows an opaque binary body and the response is HTTP/2 ...",
      "expect_skill": "attacking-grpc-protobuf",
      "also_acceptable": ["testing-apis"],
      "expected_behavior": ["Recovers the schema before testing", "..."],
      "trap_for": ["analyzing-binaries"]      // optional: skills this must NOT route to
    }

`trap_for` cases are the negative tests — a query that superficially resembles a
different skill's trigger but must route elsewhere. They are how you catch two
skills fighting over the same words.

    python3 scripts/run_evals.py --check   # CI: structural integrity + full coverage
    python3 scripts/run_evals.py --report  # human: per-skill coverage table

This runner is deterministic and needs no network or model. It verifies the
eval set is well-formed and that every shipped skill is exercised; the queries
themselves are then run against a live Claude (Claude B) to confirm routing,
per the "test with a fresh instance" loop in Anthropic's guidance.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PLUGIN_DIRS = sorted(p for p in REPO.glob("secskills-*") if (p / "skills").is_dir())
CASES = REPO / "evals" / "cases.jsonl"

REQUIRED = ("id", "query", "expect_skill", "expected_behavior")


def skill_names() -> set[str]:
    names: set[str] = set()
    for pd in PLUGIN_DIRS:
        names |= {
            d.name for d in (pd / "skills").iterdir()
            if d.is_dir() and (d / "SKILL.md").is_file()
        }
    return names


def load_cases() -> list[dict]:
    if not CASES.is_file():
        print(f"error: {CASES} not found", file=sys.stderr)
        sys.exit(2)
    cases = []
    for n, line in enumerate(CASES.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        try:
            cases.append(json.loads(line))
        except json.JSONDecodeError as e:
            print(f"error: {CASES}:{n}: invalid JSON ({e})", file=sys.stderr)
            sys.exit(1)
    return cases


def validate(cases: list[dict], skills: set[str]) -> list[str]:
    problems: list[str] = []
    seen_ids: set[str] = set()
    for c in cases:
        cid = c.get("id", "<no id>")
        for field in REQUIRED:
            if not c.get(field):
                problems.append(f"case '{cid}': missing required field '{field}'")
        if cid in seen_ids:
            problems.append(f"duplicate case id '{cid}'")
        seen_ids.add(cid)

        exp = c.get("expect_skill")
        if exp and exp not in skills:
            problems.append(f"case '{cid}': expect_skill '{exp}' is not a real skill")
        for s in c.get("also_acceptable", []):
            if s not in skills:
                problems.append(f"case '{cid}': also_acceptable '{s}' is not a real skill")
        for s in c.get("trap_for", []):
            if s not in skills:
                problems.append(f"case '{cid}': trap_for '{s}' is not a real skill")
            if s == exp:
                problems.append(f"case '{cid}': trap_for lists the expected skill '{s}'")
        if not isinstance(c.get("expected_behavior", []), list):
            problems.append(f"case '{cid}': expected_behavior must be a list")
    return problems


def coverage(cases: list[dict], skills: set[str]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for c in cases:
        counts[c.get("expect_skill", "")] += 1
    return {s: counts.get(s, 0) for s in skills}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true",
                      help="CI: fail on any structural error or uncovered skill")
    mode.add_argument("--report", action="store_true",
                      help="print a per-skill coverage table")
    args = ap.parse_args()

    skills = skill_names()
    cases = load_cases()
    problems = validate(cases, skills)
    cov = coverage(cases, skills)
    uncovered = sorted(s for s, n in cov.items() if n == 0)

    if args.report:
        print(f"{len(cases)} eval cases across {len(skills)} skills")
        print(f"covered: {len(skills) - len(uncovered)}/{len(skills)}")
        traps = sum(1 for c in cases if c.get("trap_for"))
        print(f"negative (trap) cases: {traps}\n")
        for s in sorted(skills):
            mark = " " if cov[s] else "!"
            print(f"  [{mark}] {cov[s]:2d}  {s}")
        if uncovered:
            print(f"\nuncovered ({len(uncovered)}): {', '.join(uncovered)}")
        if problems:
            print("\nstructural problems:")
            for p in problems:
                print(f"  - {p}")
        return 0

    # --check
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if uncovered:
        for s in uncovered:
            print(f"error: skill '{s}' has no eval case in evals/cases.jsonl", file=sys.stderr)
    if problems or uncovered:
        print(f"\n{len(problems)} problem(s), {len(uncovered)} uncovered skill(s)", file=sys.stderr)
        return 1
    print(f"OK: {len(cases)} eval cases, all {len(skills)} skills covered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
