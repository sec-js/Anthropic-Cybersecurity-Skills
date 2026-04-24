"""
SKILL.md validation logic — extracted from .github/workflows/validate-skills.yml.

Having these rules in a standalone module lets them be unit-tested without
running the full CI workflow, and makes it easy to run the same checks locally.

Usage:
    python scripts/validate_skills.py          # validate all skills/
    python scripts/validate_skills.py --path skills/my-new-skill/SKILL.md
"""

import os
import re
import sys
from collections import Counter
from pathlib import Path

REQUIRED_FIELDS = [
    "name", "description", "domain", "subdomain",
    "tags", "version", "author", "license",
]

# A skill name must be lowercase alphanumeric words joined by hyphens.
_KEBAB_RE = re.compile(r"^[a-z0-9-]+$")
_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.DOTALL)
_NAME_RE = re.compile(r"^name:\s*(.+)$", re.MULTILINE)

MAX_NAME_LENGTH = 64


def parse_frontmatter(content: str) -> str | None:
    """
    Extract the raw YAML frontmatter block from a SKILL.md string.

    Returns the frontmatter text (between the ``---`` delimiters) or
    ``None`` if no valid frontmatter is found.
    """
    m = _FRONTMATTER_RE.match(content)
    return m.group(1) if m else None


def extract_name(frontmatter: str) -> str | None:
    """
    Return the value of the ``name:`` field from a parsed frontmatter block,
    with surrounding whitespace and quotes stripped.  Returns ``None`` if the
    field is absent.
    """
    m = _NAME_RE.search(frontmatter)
    if not m:
        return None
    return m.group(1).strip().strip('"')


def validate_skill_content(path: str, content: str) -> list[str]:
    """
    Validate the content of a single SKILL.md file.

    Returns a (possibly empty) list of human-readable error strings.
    Each error is prefixed with ``path``.
    """
    errors: list[str] = []

    frontmatter = parse_frontmatter(content)
    if frontmatter is None:
        errors.append(f"{path}: Missing YAML frontmatter")
        return errors  # Cannot validate further without frontmatter

    for field in REQUIRED_FIELDS:
        if not re.search(rf"^{field}:", frontmatter, re.MULTILINE):
            errors.append(f"{path}: Missing required field '{field}'")

    name = extract_name(frontmatter)
    if name is not None:
        if not _KEBAB_RE.match(name):
            errors.append(f"{path}: Name '{name}' must be kebab-case")
        if len(name) > MAX_NAME_LENGTH:
            errors.append(f"{path}: Name '{name}' exceeds {MAX_NAME_LENGTH} characters")

    return errors


def collect_skill_names(skills_root: str) -> list[str]:
    """
    Walk *skills_root* and return a list of skill names (one per SKILL.md).
    Files that lack a parseable name are silently skipped.
    """
    names: list[str] = []
    for root, _dirs, files in os.walk(skills_root):
        for fname in files:
            if fname != "SKILL.md":
                continue
            path = os.path.join(root, fname)
            try:
                content = Path(path).read_text(encoding="utf-8")
            except OSError:
                continue
            fm = parse_frontmatter(content)
            if fm is None:
                continue
            name = extract_name(fm)
            if name:
                names.append(name)
    return names


def find_duplicate_names(skills_root: str) -> list[str]:
    """
    Return a sorted list of skill names that appear more than once under
    *skills_root*.
    """
    counts = Counter(collect_skill_names(skills_root))
    return sorted(name for name, count in counts.items() if count > 1)


def validate_all(skills_root: str) -> tuple[list[str], int]:
    """
    Validate every SKILL.md found under *skills_root*.

    Returns ``(errors, checked)`` where *errors* is a flat list of error
    strings and *checked* is the number of SKILL.md files examined.
    """
    all_errors: list[str] = []
    checked = 0
    for root, _dirs, files in os.walk(skills_root):
        for fname in files:
            if fname != "SKILL.md":
                continue
            path = os.path.join(root, fname)
            checked += 1
            try:
                content = Path(path).read_text(encoding="utf-8")
            except OSError as exc:
                all_errors.append(f"{path}: Cannot read file: {exc}")
                continue
            all_errors.extend(validate_skill_content(path, content))
    return all_errors, checked


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Validate SKILL.md files")
    parser.add_argument(
        "--path", help="Validate a single SKILL.md file (default: all skills/)"
    )
    parser.add_argument(
        "--skills-root", default="skills", help="Root directory to scan"
    )
    args = parser.parse_args()

    if args.path:
        content = Path(args.path).read_text(encoding="utf-8")
        errs = validate_skill_content(args.path, content)
        if errs:
            for e in errs:
                print(f"  ❌ {e}")
            sys.exit(1)
        print(f"✅ {args.path} valid")
    else:
        errors, checked = validate_all(args.skills_root)
        print(f"Checked {checked} SKILL.md files")
        if errors:
            print(f"\n{len(errors)} validation error(s):")
            for e in errors:
                print(f"  ❌ {e}")
            sys.exit(1)
        print(f"✅ All {checked} skills valid")

        duplicates = find_duplicate_names(args.skills_root)
        if duplicates:
            print(f"❌ Duplicate skill names: {duplicates}")
            sys.exit(1)
        print(f"✅ No duplicate names")
