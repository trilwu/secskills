#!/usr/bin/env python3
"""Validate SecSkills plugin structure and skill frontmatter.

Runs with no third-party dependencies so it works in any CI image.

    python3 scripts/validate.py [--strict]

--strict promotes warnings to errors.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PLUGIN_DIRS = sorted(p for p in REPO.glob("secskills-*") if (p / "skills").is_dir())

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MAX_NAME = 64
MAX_DESC = 1024
MIN_DESC = 60
MAX_SKILL_LINES = 600

DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

errors: list[str] = []
warnings: list[str] = []
verified: list[str] = []  # skills fact-checked against primary sources


def error(msg: str) -> None:
    errors.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def parse_frontmatter(path: Path) -> dict[str, str] | None:
    """Minimal YAML frontmatter parser for the flat key: value shape we use.

    Returns None when the file has no frontmatter block. List values are
    joined with ", " so callers can treat everything as a string.
    """
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        return None
    end = text.find("\n---", 4)
    if end == -1:
        return None
    block = text[4:end]

    data: dict[str, str] = {}
    key: str | None = None
    for raw in block.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.startswith((" ", "\t", "-")):
            # continuation: folded scalar or list item
            if key:
                item = raw.strip().lstrip("- ").strip()
                data[key] = (data[key] + " " + item).strip() if data[key] else item
            continue
        if ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        key = key.strip()
        data[key] = value.strip().strip("'\"")
    return data


def check_skill(skill_dir: Path) -> None:
    rel = skill_dir.relative_to(REPO)
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        error(f"{rel}: missing SKILL.md")
        return

    fm = parse_frontmatter(skill_md)
    if fm is None:
        error(f"{rel}/SKILL.md: missing or malformed YAML frontmatter")
        return

    name = fm.get("name", "")
    desc = fm.get("description", "")

    if not name:
        error(f"{rel}/SKILL.md: frontmatter is missing 'name'")
    else:
        if not NAME_RE.match(name):
            error(f"{rel}/SKILL.md: name '{name}' must be lowercase kebab-case")
        if len(name) > MAX_NAME:
            error(f"{rel}/SKILL.md: name exceeds {MAX_NAME} characters")
        if name != skill_dir.name:
            error(
                f"{rel}/SKILL.md: name '{name}' does not match directory "
                f"'{skill_dir.name}' (keep them identical so the command is predictable)"
            )

    if not desc:
        error(f"{rel}/SKILL.md: frontmatter is missing 'description'")
    else:
        if len(desc) < MIN_DESC:
            warn(f"{rel}/SKILL.md: description is short ({len(desc)} chars); "
                 "say what it does AND when to use it")
        if len(desc) > MAX_DESC:
            error(f"{rel}/SKILL.md: description exceeds {MAX_DESC} characters")
        if re.match(r"^(I |This skill |Use this )", desc):
            warn(f"{rel}/SKILL.md: write the description in third person "
                 "('Audits ...', not 'This skill audits ...')")
        if " when " not in desc.lower():
            warn(f"{rel}/SKILL.md: description has no trigger clause; add "
                 "'Use when ...' so Claude knows when to load it")

    # Optional: date of the last primary-source fact-check. Absence is not an
    # error — it means the skill is an unverified draft, which the README says
    # is the default. A malformed date is an error, since it breaks the count.
    stamp = fm.get("verified", "")
    if stamp:
        if not DATE_RE.match(stamp):
            error(f"{rel}/SKILL.md: verified '{stamp}' must be YYYY-MM-DD")
        else:
            verified.append(skill_dir.name)

    body = skill_md.read_text(encoding="utf-8")
    lines = body.count("\n") + 1
    if lines > MAX_SKILL_LINES:
        warn(f"{rel}/SKILL.md: {lines} lines (>{MAX_SKILL_LINES}); "
             "move detail into references/")

    if "## When to Use" not in body:
        warn(f"{rel}/SKILL.md: no '## When to Use' section")
    if "## When NOT to Use" not in body:
        warn(f"{rel}/SKILL.md: no '## When NOT to Use' section")

    # Referenced local files must exist.
    for ref in re.findall(r"`(references/[A-Za-z0-9._/-]+)`", body):
        if not (skill_dir / ref).is_file():
            error(f"{rel}/SKILL.md: references missing file '{ref}'")


SHARED_HEADING = "## Reading External Sources"


def check_shared_blocks() -> None:
    """Boilerplate copied across skills must stay byte-identical.

    The external-sources block carries safety caveats (never route adversary
    infrastructure or engagement URLs through a third-party extractor). If
    copies drift, some skills quietly lose those caveats, so the identity is
    enforced rather than trusted.
    """
    blocks: dict[str, list[str]] = {}
    for pd in PLUGIN_DIRS:
        for d in sorted((pd / "skills").iterdir()):
            skill_md = d / "SKILL.md"
            if not skill_md.is_file():
                continue
            text = skill_md.read_text(encoding="utf-8")
            start = text.find(SHARED_HEADING)
            if start == -1:
                continue
            end = text.find("\n## ", start + len(SHARED_HEADING))
            body = text[start:end if end != -1 else len(text)].rstrip()
            blocks.setdefault(body, []).append(d.name)

    if len(blocks) > 1:
        variants = sorted(blocks.values(), key=len, reverse=True)
        canonical, *drifted = variants
        for group in drifted:
            error(
                f"'{SHARED_HEADING}' block differs in {', '.join(sorted(group))} "
                f"(majority form used by {len(canonical)} other skills); "
                "keep shared blocks byte-identical"
            )


def check_manifests() -> None:
    market_json = REPO / ".claude-plugin" / "marketplace.json"
    try:
        market = json.loads(market_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(f".claude-plugin/marketplace.json: {exc}")
        return

    listed = {p.get("name"): p for p in market.get("plugins", [])}

    for entry in market.get("plugins", []):
        source = (REPO / entry.get("source", "").lstrip("./")).resolve()
        if not source.is_dir():
            error(f"marketplace.json: source '{entry.get('source')}' is not a directory")

    # Each plugin dir must carry its own manifest, be listed in the marketplace
    # at a matching version, and count its own skills in its description.
    for pd in PLUGIN_DIRS:
        plugin_json = pd / ".claude-plugin" / "plugin.json"
        if not plugin_json.is_file():
            error(f"{pd.name}: missing .claude-plugin/plugin.json")
            continue
        try:
            plugin = json.loads(plugin_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            error(f"{pd.name}/.claude-plugin/plugin.json: {exc}")
            continue

        for field in ("name", "version", "description"):
            if not plugin.get(field):
                error(f"{pd.name}/plugin.json: missing '{field}'")

        name = plugin.get("name")
        entry = listed.get(name)
        if entry is None:
            error(f"{pd.name}/plugin.json: '{name}' is not listed in marketplace.json")
        elif entry.get("version") != plugin.get("version"):
            error(
                f"marketplace.json and {pd.name}/plugin.json disagree on version "
                f"({entry.get('version')} vs {plugin.get('version')}); bump both together"
            )

        count = sum(
            1 for d in (pd / "skills").iterdir()
            if d.is_dir() and (d / "SKILL.md").is_file()
        )
        desc = plugin.get("description", "")
        if f"{count} " not in desc and str(count) not in desc:
            warn(f"{pd.name}/plugin.json description does not mention its skill count ({count})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = parser.parse_args()

    if not PLUGIN_DIRS:
        print("error: no secskills-* plugin dirs with a skills/ folder found", file=sys.stderr)
        return 2

    skill_names = []
    for pd in PLUGIN_DIRS:
        for d in sorted(p for p in (pd / "skills").iterdir() if p.is_dir()):
            check_skill(d)
            skill_names.append(d.name)

    # Repo-local contributor skills (.claude/skills/) are held to the same
    # structural bar, but are not shipped, so they stay out of the plugin
    # counts and the verified/total ratio for the collection.
    local_dir = REPO / ".claude" / "skills"
    local_names = []
    if local_dir.is_dir():
        for d in sorted(p for p in local_dir.iterdir() if p.is_dir()):
            check_skill(d)
            local_names.append(d.name)

    dupes = {n for n in skill_names if skill_names.count(n) > 1}
    if dupes:
        error(f"duplicate skill names across plugins: {', '.join(sorted(dupes))}")

    check_shared_blocks()

    collisions = set(skill_names) & set(local_names)
    if collisions:
        error(
            "repo-local skill names collide with shipped skills: "
            f"{', '.join(sorted(collisions))}"
        )

    check_manifests()

    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}", file=sys.stderr)

    local_note = f" (+{len(local_names)} repo-local)" if local_names else ""
    print(f"\nChecked {len(skill_names)} skills across {len(PLUGIN_DIRS)} plugins"
          f"{local_note}: {len(errors)} error(s), {len(warnings)} warning(s)")
    shipped_verified = [v for v in verified if v in set(skill_names)]
    print(f"Fact-checked against primary sources: "
          f"{len(shipped_verified)}/{len(skill_names)} "
          f"({len(skill_names) - len(shipped_verified)} unverified drafts)")

    if errors or (args.strict and warnings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
