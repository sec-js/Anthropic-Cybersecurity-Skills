"""
Tests for scripts/validate_skills.py — the SKILL.md validation logic
extracted from .github/workflows/validate-skills.yml.

All tests use in-memory strings or temporary directories so no real skill
files are modified.
"""

import os
import tempfile
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from scripts.validate_skills import (
    parse_frontmatter,
    extract_name,
    validate_skill_content,
    collect_skill_names,
    find_duplicate_names,
    validate_all,
    REQUIRED_FIELDS,
    MAX_NAME_LENGTH,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_frontmatter(**kwargs) -> str:
    """Build a minimal valid frontmatter block."""
    defaults = {
        "name": "test-skill",
        "description": "A test skill",
        "domain": "network-security",
        "subdomain": "testing",
        "tags": "[testing]",
        "version": "1.0.0",
        "author": "tester",
        "license": "Apache-2.0",
    }
    defaults.update(kwargs)
    lines = "\n".join(f"{k}: {v}" for k, v in defaults.items())
    return f"---\n{lines}\n---\n# Title\n\nContent here."


def _skill_dir(tmp_path: Path, skill_name: str, content: str) -> None:
    """Write a SKILL.md at tmp_path/skills/<skill_name>/SKILL.md."""
    skill_dir = tmp_path / "skills" / skill_name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(content)


# ---------------------------------------------------------------------------
# parse_frontmatter
# ---------------------------------------------------------------------------


class TestParseFrontmatter:
    def test_returns_content_between_delimiters(self):
        content = "---\nname: my-skill\n---\n# Body"
        fm = parse_frontmatter(content)
        assert fm is not None
        assert "name: my-skill" in fm

    def test_returns_none_when_no_frontmatter(self):
        assert parse_frontmatter("# Just a heading") is None

    def test_returns_none_when_delimiter_missing(self):
        assert parse_frontmatter("name: my-skill\n---\n# Body") is None

    def test_multiline_frontmatter(self):
        content = "---\nname: skill\ndescription: A very long\n  description\n---\n"
        fm = parse_frontmatter(content)
        assert fm is not None
        assert "description" in fm

    def test_body_excluded(self):
        content = "---\nname: skill\n---\n# This is the body"
        fm = parse_frontmatter(content)
        assert "body" not in fm.lower()


# ---------------------------------------------------------------------------
# extract_name
# ---------------------------------------------------------------------------


class TestExtractName:
    def test_extracts_plain_name(self):
        fm = "name: my-skill\ndomain: security"
        assert extract_name(fm) == "my-skill"

    def test_strips_surrounding_quotes(self):
        fm = 'name: "my-skill"\ndomain: security'
        assert extract_name(fm) == "my-skill"

    def test_returns_none_when_absent(self):
        assert extract_name("domain: security") is None

    def test_strips_whitespace(self):
        fm = "name:   spaced-name  \n"
        assert extract_name(fm) == "spaced-name"


# ---------------------------------------------------------------------------
# validate_skill_content — required fields
# ---------------------------------------------------------------------------


class TestRequiredFields:
    def test_valid_content_no_errors(self):
        errors = validate_skill_content("SKILL.md", _make_frontmatter())
        assert errors == []

    def test_missing_single_field_reported(self):
        content = _make_frontmatter()
        # Remove the author field manually
        content = content.replace("author: tester\n", "")
        errors = validate_skill_content("SKILL.md", content)
        assert any("author" in e for e in errors)

    def test_all_required_fields_checked(self):
        # Strip all required fields one by one and confirm each is reported
        for field in REQUIRED_FIELDS:
            fm_lines = "\n".join(
                f"{k}: val" for k in REQUIRED_FIELDS if k != field
            )
            content = f"---\n{fm_lines}\n---\n# Body"
            errors = validate_skill_content("test.md", content)
            assert any(field in e for e in errors), f"'{field}' not reported missing"

    def test_missing_frontmatter_returns_single_error(self):
        errors = validate_skill_content("SKILL.md", "# No frontmatter here")
        assert len(errors) == 1
        assert "frontmatter" in errors[0].lower()

    def test_path_prefix_in_error_messages(self):
        content = _make_frontmatter()
        content = content.replace("author: tester\n", "")
        errors = validate_skill_content("skills/my-skill/SKILL.md", content)
        assert all(e.startswith("skills/my-skill/SKILL.md") for e in errors)


# ---------------------------------------------------------------------------
# validate_skill_content — name format rules
# ---------------------------------------------------------------------------


class TestNameValidation:
    def test_kebab_case_valid(self):
        errors = validate_skill_content("SKILL.md", _make_frontmatter(name="valid-kebab-name"))
        assert not any("kebab" in e for e in errors)

    def test_uppercase_letter_rejected(self):
        errors = validate_skill_content("SKILL.md", _make_frontmatter(name="Invalid-Name"))
        assert any("kebab" in e.lower() for e in errors)

    def test_underscore_rejected(self):
        errors = validate_skill_content("SKILL.md", _make_frontmatter(name="under_score"))
        assert any("kebab" in e.lower() for e in errors)

    def test_spaces_rejected(self):
        errors = validate_skill_content("SKILL.md", _make_frontmatter(name="with spaces"))
        assert any("kebab" in e.lower() for e in errors)

    def test_name_at_max_length_accepted(self):
        name = "a" * MAX_NAME_LENGTH
        errors = validate_skill_content("SKILL.md", _make_frontmatter(name=name))
        assert not any("exceeds" in e for e in errors)

    def test_name_one_over_max_rejected(self):
        name = "a" * (MAX_NAME_LENGTH + 1)
        errors = validate_skill_content("SKILL.md", _make_frontmatter(name=name))
        assert any("exceeds" in e for e in errors)

    def test_digits_allowed_in_name(self):
        errors = validate_skill_content("SKILL.md", _make_frontmatter(name="skill-v2-test"))
        assert not any("kebab" in e.lower() for e in errors)

    def test_leading_hyphen_currently_accepted(self):
        # The current regex ^[a-z0-9-]+$ does not prohibit a leading hyphen.
        # This test documents the permissive behaviour; tightening the regex
        # to ^[a-z0-9][a-z0-9-]*$ would be a future improvement.
        errors = validate_skill_content("SKILL.md", _make_frontmatter(name="-bad-start"))
        assert not any("kebab" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# collect_skill_names / find_duplicate_names
# ---------------------------------------------------------------------------


class TestDuplicateDetection:
    def test_no_duplicates_when_unique_names(self, tmp_path):
        _skill_dir(tmp_path, "skill-a", _make_frontmatter(name="skill-a"))
        _skill_dir(tmp_path, "skill-b", _make_frontmatter(name="skill-b"))
        dups = find_duplicate_names(str(tmp_path / "skills"))
        assert dups == []

    def test_detects_duplicate_name(self, tmp_path):
        _skill_dir(tmp_path, "skill-a", _make_frontmatter(name="duplicate-skill"))
        _skill_dir(tmp_path, "skill-b", _make_frontmatter(name="duplicate-skill"))
        dups = find_duplicate_names(str(tmp_path / "skills"))
        assert "duplicate-skill" in dups

    def test_collect_returns_all_names(self, tmp_path):
        _skill_dir(tmp_path, "skill-a", _make_frontmatter(name="skill-a"))
        _skill_dir(tmp_path, "skill-b", _make_frontmatter(name="skill-b"))
        names = collect_skill_names(str(tmp_path / "skills"))
        assert set(names) == {"skill-a", "skill-b"}

    def test_skips_files_without_frontmatter(self, tmp_path):
        skill_dir = tmp_path / "skills" / "bad-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text("# No frontmatter")
        names = collect_skill_names(str(tmp_path / "skills"))
        assert names == []

    def test_empty_directory_no_duplicates(self, tmp_path):
        (tmp_path / "skills").mkdir()
        assert find_duplicate_names(str(tmp_path / "skills")) == []


# ---------------------------------------------------------------------------
# validate_all — integration over a temporary skill tree
# ---------------------------------------------------------------------------


class TestValidateAll:
    def test_valid_tree_no_errors(self, tmp_path):
        _skill_dir(tmp_path, "skill-a", _make_frontmatter(name="skill-a"))
        _skill_dir(tmp_path, "skill-b", _make_frontmatter(name="skill-b"))
        errors, checked = validate_all(str(tmp_path / "skills"))
        assert errors == []
        assert checked == 2

    def test_invalid_skill_reported(self, tmp_path):
        bad = _make_frontmatter().replace("author: tester\n", "")
        _skill_dir(tmp_path, "bad-skill", bad)
        errors, checked = validate_all(str(tmp_path / "skills"))
        assert any("author" in e for e in errors)
        assert checked == 1

    def test_checked_count_matches_skill_md_count(self, tmp_path):
        for i in range(5):
            _skill_dir(tmp_path, f"skill-{i}", _make_frontmatter(name=f"skill-{i}"))
        _errors, checked = validate_all(str(tmp_path / "skills"))
        assert checked == 5

    def test_empty_skills_directory(self, tmp_path):
        (tmp_path / "skills").mkdir()
        errors, checked = validate_all(str(tmp_path / "skills"))
        assert errors == []
        assert checked == 0


# ---------------------------------------------------------------------------
# Smoke test: validate the real skills/ tree produces no errors
# ---------------------------------------------------------------------------


class TestRealSkillsTree:
    def test_real_skills_all_valid(self):
        """Regression: no existing skill should fail the validator."""
        skills_root = Path(__file__).parent.parent / "skills"
        errors, checked = validate_all(str(skills_root))
        assert checked > 0, "No SKILL.md files found — check path"
        assert errors == [], f"{len(errors)} validation errors:\n" + "\n".join(errors[:10])

    def test_real_skills_no_duplicates(self):
        skills_root = Path(__file__).parent.parent / "skills"
        dups = find_duplicate_names(str(skills_root))
        assert dups == [], f"Duplicate skill names found: {dups}"
