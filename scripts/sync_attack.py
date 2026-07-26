#!/usr/bin/env python3
"""Generate the '## ATT&CK Coverage' section in each mapped SKILL.md.

`secskills-core/ttp-index.json` is the single source of truth. This script renders
it into each skill between marker comments, so the coverage a skill claims
cannot drift from the index the router skill reads.

    python3 scripts/sync_attack.py --check    # CI: fail if any file is stale
    python3 scripts/sync_attack.py --write    # regenerate in place

No third-party dependencies.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INDEX = REPO / "secskills-core" / "ttp-index.json"
PLUGIN_DIRS = sorted(p for p in REPO.glob("secskills-*") if (p / "skills").is_dir())


def skill_paths() -> dict[str, Path]:
    """Map every skill name to its SKILL.md, across all plugin dirs."""
    out: dict[str, Path] = {}
    for pd in PLUGIN_DIRS:
        for d in sorted((pd / "skills").iterdir()):
            if d.is_dir() and (d / "SKILL.md").is_file():
                out[d.name] = d / "SKILL.md"
    return out


# name -> SKILL.md path, spanning secskills-offense/defense/core.
SKILLS = skill_paths()

START = "<!-- attack:start -->"
END = "<!-- attack:end -->"

ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTIC_RE = re.compile(r"^TA\d{4}$")
ATTACK_URL = "https://attack.mitre.org/techniques"


def load_index() -> dict:
    return json.loads(INDEX.read_text(encoding="utf-8"))


def technique_url(tid: str) -> str:
    return f"{ATTACK_URL}/{tid.replace('.', '/')}/"


def validate_index(index: dict) -> list[str]:
    """Structural checks on the index itself. Does not verify against upstream."""
    problems: list[str] = []
    tactics = index.get("tactics", {})

    for tac in tactics:
        if not TACTIC_RE.match(tac):
            problems.append(f"ttp-index.json: '{tac}' is not a valid tactic ID")

    seen: set[str] = set()
    for row in index.get("techniques", []):
        tid = row.get("id", "")
        if not ID_RE.match(tid):
            problems.append(f"ttp-index.json: '{tid}' is not a valid technique ID")
        if tid in seen:
            problems.append(f"ttp-index.json: duplicate technique '{tid}'")
        seen.add(tid)
        if not row.get("name"):
            problems.append(f"ttp-index.json: {tid} has no name")
        if not row.get("tactics"):
            problems.append(f"ttp-index.json: {tid} has no tactics")
        for tac in row.get("tactics", []):
            if tac not in tactics:
                problems.append(f"ttp-index.json: {tid} references unknown tactic '{tac}'")
        if not row.get("skills"):
            problems.append(f"ttp-index.json: {tid} maps to no skill")
        for skill in row.get("skills", []):
            if skill not in SKILLS:
                problems.append(f"ttp-index.json: {tid} maps to unknown skill '{skill}'")

        # A sub-technique should not appear without a home tactic its parent lacks.
        if "." in tid:
            parent = tid.split(".")[0]
            if parent in seen and not set(row["tactics"]):
                problems.append(f"ttp-index.json: {tid} has no tactics but parent {parent} does")

    for skill in index.get("_unmapped", {}):
        if skill.startswith("_") or skill == "note":
            continue
        if skill not in SKILLS:
            problems.append(f"ttp-index.json: _unmapped references unknown skill '{skill}'")

    return problems


def by_skill(index: dict) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for row in index.get("techniques", []):
        for skill in row.get("skills", []):
            grouped[skill].append(row)
    for rows in grouped.values():
        rows.sort(key=lambda r: r["id"])
    return grouped


def render(skill: str, rows: list[dict], index: dict) -> str:
    tactics = index["tactics"]
    universal = index["_universal"]

    # Group under the technique's primary tactic only. Techniques like T1078
    # sit under four tactics; repeating the row four times is noise, so the
    # secondary tactics are named inline instead.
    per_tactic: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        per_tactic[row["tactics"][0]].append(row)

    lines = [
        START,
        "",
        "## ATT&CK Coverage",
        "",
        "_Generated from `secskills-core/ttp-index.json` — edit that file, then run",
        "`python3 scripts/sync_attack.py --write`. Re-verify IDs against the",
        "current ATT&CK release before citing them in a report._",
        "",
    ]

    for tac in tactics:
        if tac not in per_tactic:
            continue
        lines.append(f"**{tactics[tac]}** ({tac})")
        lines.append("")
        for row in sorted(per_tactic[tac], key=lambda r: r["id"]):
            extra_tactics = [tactics[t] for t in row["tactics"][1:]]
            cross = f" _(also {', '.join(extra_tactics)})_" if extra_tactics else ""
            others = [s for s in row["skills"] if s != skill]
            also = f" — see also `{'`, `'.join(others)}`" if others else ""
            lines.append(
                f"- [{row['id']}]({technique_url(row['id'])}) {row['name']}{cross}{also}"
            )
        lines.append("")

    lines.extend([
        f"Detection content for any of these: `{universal['detection']}`. "
        f"Proactive search: `{universal['hunting']}`. "
        f"Post-compromise: `{universal['response']}`.",
        "",
        END,
    ])
    return "\n".join(lines)


def apply(path: Path, block: str) -> tuple[bool, str]:
    """Return (changed, new_text). Inserts before '## References' if present."""
    text = path.read_text(encoding="utf-8")

    if START in text and END in text:
        pre, rest = text.split(START, 1)
        _, post = rest.split(END, 1)
        new = pre + block + post
        return new != text, new

    anchor = re.search(r"^## References\s*$", text, re.M)
    if anchor:
        new = text[: anchor.start()] + block + "\n\n" + text[anchor.start():]
    else:
        new = text.rstrip("\n") + "\n\n" + block + "\n"
    return new != text, new


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="fail if any file is stale")
    mode.add_argument("--write", action="store_true", help="regenerate in place")
    args = parser.parse_args()

    if not INDEX.is_file():
        print(f"error: {INDEX} not found", file=sys.stderr)
        return 2

    index = load_index()

    problems = validate_index(index)
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if problems:
        return 1

    grouped = by_skill(index)
    stale: list[str] = []
    written = 0

    for skill, rows in sorted(grouped.items()):
        path = SKILLS[skill]
        block = render(skill, rows, index)
        changed, new_text = apply(path, block)
        if not changed:
            continue
        if args.write:
            path.write_text(new_text, encoding="utf-8")
            written += 1
        else:
            stale.append(skill)

    # A skill must be either mapped or explicitly declared unmapped.
    unmapped = set(k for k in index.get("_unmapped", {}) if k != "note")
    all_skills = set(SKILLS)
    unaccounted = all_skills - set(grouped) - unmapped
    if unaccounted:
        for skill in sorted(unaccounted):
            print(
                f"error: skill '{skill}' is neither in ttp-index.json techniques "
                "nor listed under _unmapped",
                file=sys.stderr,
            )
        return 1

    if args.write:
        print(f"Synced {len(grouped)} skills from ttp-index.json ({written} updated, "
              f"{len(unmapped)} declared unmapped)")
        return 0

    if stale:
        for skill in stale:
            print(f"error: {skill}/SKILL.md ATT&CK section is stale", file=sys.stderr)
        print("\nRun: python3 scripts/sync_attack.py --write", file=sys.stderr)
        return 1

    print(f"ATT&CK sections are in sync across {len(grouped)} skills "
          f"({len(index['techniques'])} techniques indexed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
