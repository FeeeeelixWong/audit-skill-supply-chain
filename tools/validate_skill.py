#!/usr/bin/env python3
"""Validate the packaged Codex skill without external dependencies."""

from __future__ import annotations

import py_compile
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "audit-skill-supply-chain"


def fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def parse_frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        fail("SKILL.md must start with YAML frontmatter")
    end = text.find("\n---", 4)
    if end == -1:
        fail("SKILL.md frontmatter is not closed")
    result: dict[str, str] = {}
    for raw in text[4:end].splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        result[key.strip()] = value.strip()
    return result


def main() -> int:
    skill_md = SKILL / "SKILL.md"
    if not skill_md.exists():
        fail(f"missing {skill_md}")

    frontmatter = parse_frontmatter(skill_md.read_text(encoding="utf-8"))
    name = frontmatter.get("name", "").strip("\"'")
    description = frontmatter.get("description", "").strip()
    if name != "audit-skill-supply-chain":
        fail(f"unexpected skill name: {name!r}")
    if not description:
        fail("missing skill description")
    if not re.fullmatch(r"[a-z0-9-]{1,64}", name):
        fail("skill name must be lowercase hyphen-case")

    required = [
        SKILL / "agents" / "openai.yaml",
        SKILL / "references" / "risk-model.md",
        SKILL / "references" / "provenance-and-isolation.md",
        SKILL / "references" / "report-template.md",
        SKILL / "scripts" / "scan_skill.py",
    ]
    for path in required:
        if not path.exists():
            fail(f"missing {path.relative_to(ROOT)}")

    py_compile.compile(str(SKILL / "scripts" / "scan_skill.py"), doraise=True)
    print("Skill package is valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
