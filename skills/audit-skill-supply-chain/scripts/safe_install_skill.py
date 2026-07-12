#!/usr/bin/env python3
"""Install a skill only after the scanner allows the exact candidate."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from argparse import Namespace
from dataclasses import asdict
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

import scan_skill  # noqa: E402


BLOCKING_GATES = {"BLOCK", "QUARANTINE"}


def parse_skill_name(skill_md: Path) -> str:
    text = skill_md.read_text(encoding="utf-8", errors="replace")
    if not text.startswith("---\n"):
        raise ValueError("SKILL.md is missing frontmatter")
    end = text.find("\n---", 4)
    if end == -1:
        raise ValueError("SKILL.md frontmatter is not closed")
    for raw in text[4:end].splitlines():
        if raw.startswith("name:"):
            return raw.split(":", 1)[1].strip().strip("\"'")
    raise ValueError("SKILL.md is missing name")


def run_scan(args: argparse.Namespace) -> dict:
    findings: list[scan_skill.Finding] = []
    scan_args = Namespace(
        source_url=args.source_url,
        expected_commit=args.expected_commit,
        artifact=args.artifact,
        expected_sha256=args.expected_sha256,
        installed_baseline=False,
    )
    scan_skill.scan_provenance(args.candidate, scan_args, findings)
    scan_skill.scan_structure(args.candidate, findings)
    scan_skill.scan_files(args.candidate, 512_000, findings)
    return {
        "target": str(args.candidate),
        "gate": scan_skill.gate_for_findings(findings),
        "summary": scan_skill.summarize(findings),
        "findings": [asdict(finding) for finding in findings],
    }


def copy_skill(candidate: Path, destination: Path, replace: bool) -> None:
    if destination.exists():
        if not replace:
            raise FileExistsError(f"destination exists: {destination}")
        shutil.rmtree(destination)

    def ignore(_dir: str, names: list[str]) -> set[str]:
        return {name for name in names if name in {".git", "__pycache__", ".pytest_cache"}}

    shutil.copytree(candidate, destination, symlinks=True, ignore=ignore)


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely install a skill after pre-install audit.")
    parser.add_argument("candidate", help="Candidate skill directory already acquired in quarantine")
    parser.add_argument("--dest-root", default=str(Path.home() / ".codex" / "skills"), help="Live skill root")
    parser.add_argument("--source-url", help="Approved GitHub repository URL")
    parser.add_argument("--expected-commit", help="Approved full 40-character Git commit SHA")
    parser.add_argument("--artifact", help="Downloaded release archive or asset used to create the candidate")
    parser.add_argument("--expected-sha256", help="Expected SHA256 for --artifact, or tree digest")
    parser.add_argument("--allow-conditions", action="store_true", help="Allow ALLOW WITH CONDITIONS installs")
    parser.add_argument("--replace", action="store_true", help="Replace existing destination skill directory")
    parser.add_argument("--dry-run", action="store_true", help="Scan and report without copying")
    args = parser.parse_args()

    args.candidate = Path(args.candidate).expanduser().resolve()
    if not args.candidate.is_dir():
        print(f"error: candidate is not a directory: {args.candidate}", file=sys.stderr)
        return 1

    skill_md = args.candidate / "SKILL.md"
    if not skill_md.exists():
        print("error: candidate does not contain SKILL.md", file=sys.stderr)
        return 1

    try:
        skill_name = parse_skill_name(skill_md)
        result = run_scan(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    gate = result.get("gate", "BLOCK")
    print(f"Gate: {gate}")
    print("Findings: " + ", ".join(f"{k}={v}" for k, v in result.get("summary", {}).items()))

    if gate in BLOCKING_GATES:
        print("Install blocked. Keep the candidate in quarantine and review findings.")
        return 2
    if gate == "ALLOW WITH CONDITIONS" and not args.allow_conditions:
        print("Install requires --allow-conditions after manual review.")
        return 2

    destination = Path(args.dest_root).expanduser().resolve() / skill_name
    if args.dry_run:
        print(f"Dry run: would install {args.candidate} -> {destination}")
        return 0

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        copy_skill(args.candidate, destination, args.replace)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Installed: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
