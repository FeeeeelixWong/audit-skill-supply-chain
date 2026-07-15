#!/usr/bin/env python3
"""Create project-level instruction adapters for mainstream agent CLIs."""

from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "audit-skill-supply-chain"


POLICY = """# Audit Skill Supply Chain Policy

Before installing, importing, updating, or trusting any third-party agent skill:

1. Acquire the candidate in a quarantine directory, not a live skill directory.
2. Verify provenance with a full GitHub commit SHA or a release SHA256 checksum.
3. Run the scanner before copying anything into a live skill path.
4. Block install if findings include credential access, private-data exfiltration, wallet/payment risk, prompt injection, remote code execution, persistence, or provenance mismatch.
5. If the gate is `QUARANTINE` or `BLOCK`, tell the user and do not install.

Preferred commands:

```bash
python3 {skill_path}/scripts/audit_skill.py scan /path/to/quarantined-skill \\
  --source-url https://github.com/owner/repo \\
  --expected-commit <40-character-commit-sha>

python3 {skill_path}/scripts/audit_skill.py install /path/to/quarantined-skill \\
  --cli both \\
  --source-url https://github.com/owner/repo \\
  --expected-commit <40-character-commit-sha>
```

For installed-skill baseline scans:

```bash
python3 {skill_path}/scripts/audit_skill.py baseline \\
  --report ~/.agent-skill-audit/installed-skills-baseline.md

python3 {skill_path}/scripts/audit_skill.py verify
```
"""


def default_skill_path() -> str:
    candidates = [
        Path.home() / ".codex" / "skills" / SKILL_NAME,
        Path.home() / ".claude" / "skills" / SKILL_NAME,
        ROOT / "skills" / SKILL_NAME,
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return f"~/.codex/skills/{SKILL_NAME}"


def adapter_content(kind: str, skill_path: str) -> str:
    policy = POLICY.format(skill_path=skill_path)
    if kind == "cursor":
        return f"""---
description: Require skill supply-chain audits before installing agent skills
alwaysApply: true
---

{policy}
"""
    return policy


def target_files(project: Path, targets: list[str]) -> list[tuple[str, Path]]:
    if "all" in targets:
        targets = ["agents", "claude", "gemini", "copilot", "cursor"]

    mapping = {
        "agents": project / "AGENTS.md",
        "claude": project / "CLAUDE.md",
        "gemini": project / "GEMINI.md",
        "copilot": project / ".github" / "copilot-instructions.md",
        "cursor": project / ".cursor" / "rules" / "audit-skill-supply-chain.mdc",
    }
    result: list[tuple[str, Path]] = []
    for target in targets:
        if target not in mapping:
            raise ValueError(f"unknown target: {target}")
        result.append((target, mapping[target]))
    return result


def write_or_append(path: Path, content: str, replace: bool, dry_run: bool) -> None:
    marker = "<!-- audit-skill-supply-chain -->"
    block = f"{marker}\n{content.rstrip()}\n{marker}\n"
    if dry_run:
        print(f"Dry run: would update {path}")
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    if replace or not path.exists():
        path.write_text(block, encoding="utf-8")
        print(f"Wrote: {path}")
        return

    existing = path.read_text(encoding="utf-8", errors="replace")
    if marker in existing:
        before, _sep, rest = existing.partition(marker)
        _old, _sep2, after = rest.partition(marker)
        path.write_text(before.rstrip() + "\n\n" + block + after.lstrip(), encoding="utf-8")
    else:
        path.write_text(existing.rstrip() + "\n\n" + block, encoding="utf-8")
    print(f"Updated: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Create instruction adapters for agent CLIs.")
    parser.add_argument("--project", default=".", help="Project directory to update")
    parser.add_argument(
        "--target",
        action="append",
        choices=["agents", "claude", "gemini", "copilot", "cursor", "all"],
        default=[],
        help="Adapter target. Repeat for multiple targets. Defaults to all.",
    )
    parser.add_argument(
        "--skill-path",
        default=None,
        help="Installed path to audit-skill-supply-chain used in generated instructions",
    )
    parser.add_argument("--replace", action="store_true", help="Replace target files instead of appending/updating block")
    parser.add_argument("--dry-run", action="store_true", help="Show files without writing")
    args = parser.parse_args()

    project = Path(args.project).expanduser().resolve()
    skill_path = args.skill_path or default_skill_path()
    targets = args.target or ["all"]
    for target, path in target_files(project, targets):
        write_or_append(path, adapter_content(target, skill_path), args.replace, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
