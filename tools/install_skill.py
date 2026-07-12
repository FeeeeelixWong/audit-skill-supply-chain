#!/usr/bin/env python3
"""Install this audit skill into supported local agent CLI skill directories."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SKILL_NAME = "audit-skill-supply-chain"
SKILL_DIR = ROOT / "skills" / SKILL_NAME
DEST_ROOTS = {
    "codex": Path.home() / ".codex" / "skills",
    "claude": Path.home() / ".claude" / "skills",
}


def copy_skill(destination: Path, replace: bool, dry_run: bool) -> None:
    if dry_run:
        print(f"Dry run: would install {SKILL_DIR} -> {destination}")
        return
    if destination.exists():
        if not replace:
            raise FileExistsError(f"destination exists: {destination}; pass --replace to overwrite")
        shutil.rmtree(destination)

    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {name for name in names if name in {".git", "__pycache__", ".pytest_cache"}}

    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(SKILL_DIR, destination, symlinks=True, ignore=ignore)
    print(f"Installed: {destination}")


def selected_targets(raw_targets: list[str]) -> list[str]:
    if "all" in raw_targets:
        return ["codex", "claude"]
    seen: list[str] = []
    for target in raw_targets:
        if target not in seen:
            seen.append(target)
    return seen


def main() -> int:
    parser = argparse.ArgumentParser(description="Install audit-skill-supply-chain into local agent CLIs.")
    parser.add_argument(
        "--target",
        action="append",
        choices=["codex", "claude", "all"],
        default=[],
        help="Install target. Repeat for multiple targets. Defaults to all.",
    )
    parser.add_argument("--replace", action="store_true", help="Replace an existing installed copy")
    parser.add_argument("--dry-run", action="store_true", help="Show destinations without copying")
    args = parser.parse_args()

    if not SKILL_DIR.exists():
        raise SystemExit(f"missing skill directory: {SKILL_DIR}")

    targets = selected_targets(args.target or ["all"])
    for target in targets:
        copy_skill(DEST_ROOTS[target] / SKILL_NAME, args.replace, args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
