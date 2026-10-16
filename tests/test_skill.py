"""Structural checks for the shipped Agent Skill (no YAML dependency needed)."""
from __future__ import annotations

import re
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[1] / "skills"
ALLOWED_KEYS = {"name", "description", "license", "allowed-tools", "metadata"}


def _skills():
    return sorted(path for path in SKILL_ROOT.iterdir() if (path / "SKILL.md").is_file())


def test_a_skill_is_shipped():
    assert [path.name for path in _skills()] == ["ddt-dos-reverse-engineering"]


def test_frontmatter_matches_the_agent_skills_specification():
    for skill in _skills():
        text = (skill / "SKILL.md").read_text(encoding="utf-8")
        assert text.startswith("---\n"), f"{skill.name}: no frontmatter"
        block = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
        assert block, f"{skill.name}: unterminated frontmatter"
        keys = {}
        for line in block.group(1).splitlines():
            key, _, value = line.partition(":")
            keys[key.strip()] = value.strip()
        assert set(keys) <= ALLOWED_KEYS, f"{skill.name}: unexpected keys {set(keys) - ALLOWED_KEYS}"
        name = keys["name"]
        assert name == skill.name, f"{skill.name}: frontmatter name {name!r} differs from folder"
        assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name), f"{name}: not hyphen-case"
        assert len(name) <= 64, f"{name}: too long"
        description = keys["description"]
        assert len(description) > 40 and "TODO" not in description
        assert "TODO" not in text, f"{skill.name}: unfinished placeholder"


def test_referenced_files_exist():
    for skill in _skills():
        text = (skill / "SKILL.md").read_text(encoding="utf-8")
        linked = re.findall(r"\]\((?!#)([^)#\s]+)\)", text)
        assert linked, f"{skill.name}: SKILL.md links no supporting files"
        for target in linked:
            if "://" in target:
                continue
            assert (skill / target).is_file(), f"{skill.name}: missing {target}"
